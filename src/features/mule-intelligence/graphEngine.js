import { Graph } from 'graphology';
import louvain from 'graphology-communities-louvain';
import { supabase } from '../../db/supabaseClient.js';
import { hashToken } from './hashUtil.js';
import { userRepository } from '../../db/userRepository.js';
import { telemetryRepository } from '../../db/telemetryRepository.js';

/**
 * Graph Engine
 * Builds and analyzes the entity relationship graph using Graphology and Louvain community detection,
 * and propagates reputation using Personalized PageRank.
 */

export const graphEngine = {
  /**
   * Links shared attributes (device, IP, phone, beneficiary) between sender and receiver.
   * Runs at transaction-time.
   */
  async linkSharedAttributes(senderAccountId, receiverAccountId) {
    if (!senderAccountId || !receiverAccountId) return;

    try {
      const edgesToUpsert = [];

      // 1. Resolve users to fetch telemetry
      const senderUser = await userRepository.findUserByAccountId(senderAccountId);
      const receiverUser = await userRepository.findUserByAccountId(receiverAccountId);

      if (!senderUser || !receiverUser) return;

      // A. Create Beneficiary edge
      edgesToUpsert.push({
        account_a: senderAccountId,
        account_b: receiverAccountId,
        edge_type: 'beneficiary',
        token_hash: hashToken(receiverAccountId),
        weight: 1
      });

      // Fetch telemetry for both users
      const senderEvents = await telemetryRepository.getEventsForUser(senderUser.user_id);
      const receiverEvents = await telemetryRepository.getEventsForUser(receiverUser.user_id);

      // B. Analyze shared device IDs
      const senderDevices = new Set(senderEvents.map(e => e.device_id).filter(Boolean));
      const receiverDevices = new Set(receiverEvents.map(e => e.device_id).filter(Boolean));
      for (const dev of senderDevices) {
        if (receiverDevices.has(dev)) {
          edgesToUpsert.push({
            account_a: senderAccountId,
            account_b: receiverAccountId,
            edge_type: 'device',
            token_hash: hashToken(dev),
            weight: 2 // Higher weight for shared device
          });
        }
      }

      // C. Analyze shared IP addresses
      const senderIps = new Set(senderEvents.map(e => e.ip_address).filter(Boolean));
      const receiverIps = new Set(receiverEvents.map(e => e.ip_address).filter(Boolean));
      for (const ip of senderIps) {
        if (receiverIps.has(ip)) {
          edgesToUpsert.push({
            account_a: senderAccountId,
            account_b: receiverAccountId,
            edge_type: 'ip',
            token_hash: hashToken(ip),
            weight: 1.5
          });
        }
      }

      // D. Analyze shared phone number
      if (senderUser.phone && receiverUser.phone && senderUser.phone.trim() === receiverUser.phone.trim()) {
        edgesToUpsert.push({
          account_a: senderAccountId,
          account_b: receiverAccountId,
          edge_type: 'phone',
          token_hash: hashToken(senderUser.phone),
          weight: 3 // Very high weight for matching phone
        });
      }

      // Perform upserts in Supabase
      if (edgesToUpsert.length > 0) {
        // Map to format suitable for Supabase insertion with last_seen
        const upsertPayload = edgesToUpsert.map(edge => ({
          ...edge,
          last_seen: new Date().toISOString()
        }));

        const { error } = await supabase
          .from('entity_edges')
          .upsert(upsertPayload, { onConflict: 'account_a,account_b,edge_type,token_hash' });

        if (error) {
          console.error('[MMIE] Error upserting entity edges:', error.message);
        }
      }
    } catch (err) {
      console.error('[MMIE] linkSharedAttributes error:', err.message);
    }
  },

  /**
   * Rebuilds graph in-memory, computes personalized PageRank and Louvain partitions,
   * and updates the standing posture scores of all nodes in the database.
   */
  async rebuildAndAnalyzeNetwork() {
    try {
      // 1. Fetch all edges
      const { data: dbEdges, error: edgesErr } = await supabase
        .from('entity_edges')
        .select('*');

      if (edgesErr) throw edgesErr;
      if (!dbEdges || dbEdges.length === 0) {
        console.log('[MMIE] No entity edges found to analyze.');
        return;
      }

      // 2. Fetch all fraud reports to seed PageRank
      const { data: dbFrauds, error: fraudErr } = await supabase
        .from('fraud_reports')
        .select('account_id');

      if (fraudErr) throw fraudErr;
      const fraudSeeds = new Set((dbFrauds || []).map(f => f.account_id));

      // 3. Build Graphology Undirected Graph
      const graph = new Graph({ type: 'undirected' });

      dbEdges.forEach(edge => {
        if (!graph.hasNode(edge.account_a)) graph.addNode(edge.account_a);
        if (!graph.hasNode(edge.account_b)) graph.addNode(edge.account_b);

        // Add or aggregate edge weights
        if (!graph.hasEdge(edge.account_a, edge.account_b)) {
          graph.addEdge(edge.account_a, edge.account_b, {
            weight: parseFloat(edge.weight) || 1.0
          });
        } else {
          // Cumulative weight for multi-attributes
          const curWeight = graph.getEdgeAttribute(edge.account_a, edge.account_b, 'weight');
          graph.setEdgeAttribute(edge.account_a, edge.account_b, 'weight', curWeight + (parseFloat(edge.weight) || 1.0));
        }
      });

      const nodes = graph.nodes();
      if (nodes.length === 0) return;

      // 4. Run Louvain Community Detection
      const communityMapping = louvain(graph);

      // 5. Run Personalized PageRank (damping 0.85, max 3 hops/iterations)
      const pageRankScores = this.runPersonalizedPageRank(graph, fraudSeeds, 0.85, 3);

      // 6. Write results to database
      for (const node of nodes) {
        const pScore = pageRankScores[node] || 0.0;
        const commId = String(communityMapping[node] !== undefined ? communityMapping[node] : 'default');

        // Check if there is an existing posture row
        const { data: existing } = await supabase
          .from('mule_posture')
          .select('posture_score, hawkes_intensity')
          .eq('account_id', node)
          .maybeSingle();

        const curPageRankLR = 1.0 + (pScore * 1500);
        
        // Calculate new receiver standing posture score (independent of transaction time)
        // Standing posture = PageRank reputation + Hawkes decay-inflow indicators
        const curHawkes = existing?.hawkes_intensity || 0.0;
        
        // Final posture score combines network risk and transaction flow volume (0-100 gauge)
        const combinedScore = Math.min(100, Math.round((pScore * 500) + (curHawkes * 10)));

        // Preserve the higher of existing posture_score (set by transaction-time assessment)
        // vs. the background recalculated combinedScore to avoid overwriting real assessments
        const existingScore = existing?.posture_score || 0;
        const finalScore = Math.max(existingScore, combinedScore);

        await supabase
          .from('mule_posture')
          .upsert({
            account_id: node,
            graph_reputation: pScore,
            community_id: commId,
            posture_score: finalScore,
            last_updated: new Date().toISOString()
          }, { onConflict: 'account_id' });
      }

      console.log(`[MMIE] Successfully re-analyzed network of ${nodes.length} nodes.`);
    } catch (err) {
      console.error('[MMIE] rebuildAndAnalyzeNetwork failed:', err.message);
    }
  },

  /**
   * Implements custom Personalized PageRank power iteration.
   */
  runPersonalizedPageRank(graph, seeds, damping = 0.85, maxHops = 3) {
    const nodes = graph.nodes();
    const n = nodes.length;
    const scores = {};

    // 1. Initialize personalization vector
    const personalization = {};
    let seedCount = 0;
    seeds.forEach(s => {
      if (graph.hasNode(s)) seedCount++;
    });

    nodes.forEach(node => {
      if (seedCount > 0) {
        personalization[node] = seeds.has(node) ? 1.0 / seedCount : 0.0;
      } else {
        personalization[node] = 1.0 / n; // Uniform fallback
      }
      scores[node] = personalization[node]; // Initial scores
    });

    // 2. Power Iterations (max hops = 3)
    for (let hop = 0; hop < maxHops; hop++) {
      const nextScores = {};
      nodes.forEach(node => {
        nextScores[node] = 0.0;
      });

      let danglingSum = 0.0;

      nodes.forEach(u => {
        const neighbors = graph.neighbors(u);
        const degree = neighbors.length;

        if (degree === 0) {
          danglingSum += scores[u];
        } else {
          neighbors.forEach(v => {
            // Distribute weight based on edge weights
            const edgeWeight = graph.getEdgeAttribute(u, v, 'weight') || 1.0;
            
            // Sum of weights for u's edges
            const sumWeights = graph.neighbors(u).reduce((sum, nbr) => sum + (graph.getEdgeAttribute(u, nbr, 'weight') || 1.0), 0);

            const fraction = sumWeights > 0 ? edgeWeight / sumWeights : 1.0 / degree;
            nextScores[v] += scores[u] * fraction;
          });
        }
      });

      // Apply damping and personalization vector
      nodes.forEach(node => {
        const val = nextScores[node] + danglingSum * personalization[node];
        scores[node] = (1 - damping) * personalization[node] + damping * val;
      });
    }

    return scores;
  },

  /**
   * Exposes community clusters / ring data for cytoscape UI console
   */
  async getRingsForAccount(accountId) {
    try {
      if (!accountId) {
        // Return enriched full graph clusters as rings
        const { data: postures } = await supabase.from('mule_posture').select('*');
        const { data: edges } = await supabase.from('entity_edges').select('*');
        const memberIds = (postures || []).map(m => m.account_id);
        const { data: userDetails } = await supabase
          .from('users')
          .select('account_id, user_id, full_name')
          .in('account_id', memberIds);

        const detailsMap = {};
        const userIds = [];
        const userIdToAccountId = {};
        (userDetails || []).forEach(u => {
          userIds.push(u.user_id);
          userIdToAccountId[u.user_id] = u.account_id;
          detailsMap[u.account_id] = {
            full_name: u.full_name || u.account_id,
            total_sent: 0,
            total_received: 0
          };
        });

        if (userIds.length > 0) {
          const { data: sentTxns } = await supabase
            .from('transactions')
            .select('sender_user_id, amount')
            .in('sender_user_id', userIds);
          (sentTxns || []).forEach(t => {
            const accId = userIdToAccountId[t.sender_user_id];
            if (accId && detailsMap[accId]) {
              detailsMap[accId].total_sent += parseFloat(t.amount) || 0;
            }
          });

          const { data: receivedTxns } = await supabase
            .from('transactions')
            .select('receiver_user_id, amount')
            .in('receiver_user_id', userIds);
          (receivedTxns || []).forEach(t => {
            const accId = userIdToAccountId[t.receiver_user_id];
            if (accId && detailsMap[accId]) {
              detailsMap[accId].total_received += parseFloat(t.amount) || 0;
            }
          });
        }

        // Fetch assessments to map dynamic mule score (latest assessment first)
        const assessmentsMap = {};
        if (memberIds.length > 0) {
          const { data: receiverAssess } = await supabase
            .from('mule_assessments')
            .select('receiver_account_id, mule_confidence, created_at')
            .in('receiver_account_id', memberIds)
            .order('created_at', { ascending: false });

          (receiverAssess || []).forEach(ass => {
            if (assessmentsMap[ass.receiver_account_id] === undefined) {
              assessmentsMap[ass.receiver_account_id] = ass.mule_confidence;
            }
          });
        }

        let communityTransactions = [];
        if (userIds.length > 0) {
          const { data: sentTxns } = await supabase
            .from('transactions')
            .select('transaction_id, sender_user_id, receiver_user_id, amount, currency, transaction_status, transaction_timestamp, description')
            .in('sender_user_id', userIds);

          const { data: recvTxns } = await supabase
            .from('transactions')
            .select('transaction_id, sender_user_id, receiver_user_id, amount, currency, transaction_status, transaction_timestamp, description')
            .in('receiver_user_id', userIds);

          const txMap = new Map();
          [...(sentTxns || []), ...(recvTxns || [])].forEach(t => {
            if (!txMap.has(t.transaction_id)) {
              txMap.set(t.transaction_id, t);
            }
          });

          const sortedTxns = Array.from(txMap.values()).sort((a, b) => 
            new Date(b.transaction_timestamp || b.created_at || 0) - new Date(a.transaction_timestamp || a.created_at || 0)
          );

          communityTransactions = sortedTxns.map(t => ({
            transaction_id: t.transaction_id,
            sender_account_id: userIdToAccountId[t.sender_user_id] || t.sender_user_id,
            sender_name: detailsMap[userIdToAccountId[t.sender_user_id]]?.full_name || userIdToAccountId[t.sender_user_id] || t.sender_user_id,
            receiver_account_id: userIdToAccountId[t.receiver_user_id] || t.receiver_user_id,
            receiver_name: detailsMap[userIdToAccountId[t.receiver_user_id]]?.full_name || userIdToAccountId[t.receiver_user_id] || t.receiver_user_id,
            amount: parseFloat(t.amount) || 0,
            currency: t.currency || 'INR',
            status: t.transaction_status || 'completed',
            timestamp: t.transaction_timestamp,
            description: t.description || 'Transfer'
          }));
        }

        const enrichedPostures = (postures || []).map(m => {
          const assessScore = assessmentsMap[m.account_id] !== undefined ? assessmentsMap[m.account_id] : 0;
          const standingScore = m.posture_score || 0;
          return {
            ...m,
            full_name: detailsMap[m.account_id]?.full_name || m.account_id,
            total_sent: detailsMap[m.account_id]?.total_sent || 0,
            total_received: detailsMap[m.account_id]?.total_received || 0,
            mule_score: Math.max(standingScore, assessScore)
          };
        });
        return { postures: enrichedPostures, edges: edges || [], transactions: communityTransactions };
      }

      // 1. Fetch current account posture to identify community
      const { data: currentPosture } = await supabase
        .from('mule_posture')
        .select('*')
        .eq('account_id', accountId)
        .maybeSingle();

      if (!currentPosture || !currentPosture.community_id) {
        return { postures: [], edges: [] };
      }

      const communityId = currentPosture.community_id;

      // 2. Fetch all members of this community
      const { data: ringMembers } = await supabase
        .from('mule_posture')
        .select('*')
        .eq('community_id', communityId);

      const memberIds = (ringMembers || []).map(m => m.account_id);

      // Fetch user details for display cards
      const { data: userDetails } = await supabase
        .from('users')
        .select('account_id, user_id, full_name')
        .in('account_id', memberIds);

      const detailsMap = {};
      const userIds = [];
      const userIdToAccountId = {};
      (userDetails || []).forEach(u => {
        userIds.push(u.user_id);
        userIdToAccountId[u.user_id] = u.account_id;
        detailsMap[u.account_id] = {
          full_name: u.full_name || u.account_id,
          total_sent: 0,
          total_received: 0
        };
      });

      if (userIds.length > 0) {
        const { data: sentTxns } = await supabase
          .from('transactions')
          .select('sender_user_id, amount')
          .in('sender_user_id', userIds);
        (sentTxns || []).forEach(t => {
          const accId = userIdToAccountId[t.sender_user_id];
          if (accId && detailsMap[accId]) {
            detailsMap[accId].total_sent += parseFloat(t.amount) || 0;
          }
        });

        const { data: receivedTxns } = await supabase
          .from('transactions')
          .select('receiver_user_id, amount')
          .in('receiver_user_id', userIds);
        (receivedTxns || []).forEach(t => {
          const accId = userIdToAccountId[t.receiver_user_id];
          if (accId && detailsMap[accId]) {
            detailsMap[accId].total_received += parseFloat(t.amount) || 0;
          }
        });
      }

      // Fetch assessments to map dynamic mule score (latest assessment first)
      const assessmentsMap = {};
      if (memberIds.length > 0) {
        const { data: receiverAssess } = await supabase
          .from('mule_assessments')
          .select('receiver_account_id, mule_confidence, created_at')
          .in('receiver_account_id', memberIds)
          .order('created_at', { ascending: false });

        (receiverAssess || []).forEach(ass => {
          if (assessmentsMap[ass.receiver_account_id] === undefined) {
            assessmentsMap[ass.receiver_account_id] = ass.mule_confidence;
          }
        });
      }

      const enrichedPostures = (ringMembers || []).map(m => {
        const assessScore = assessmentsMap[m.account_id] !== undefined ? assessmentsMap[m.account_id] : 0;
        const standingScore = m.posture_score || 0;
        return {
          ...m,
          full_name: detailsMap[m.account_id]?.full_name || m.account_id,
          total_sent: detailsMap[m.account_id]?.total_sent || 0,
          total_received: detailsMap[m.account_id]?.total_received || 0,
          mule_score: Math.max(standingScore, assessScore)
        };
      });

      // Fetch all edges connecting members in this community
      const { data: ringEdges } = await supabase
        .from('entity_edges')
        .select('*')
        .in('account_a', memberIds)
        .in('account_b', memberIds);

      // Fetch all direct money flows involving community members for complete money movement tracing
      let communityTransactions = [];
      if (userIds.length > 0) {
        const { data: sentTxns } = await supabase
          .from('transactions')
          .select('transaction_id, sender_user_id, receiver_user_id, amount, currency, transaction_status, transaction_timestamp, description')
          .in('sender_user_id', userIds);

        const { data: recvTxns } = await supabase
          .from('transactions')
          .select('transaction_id, sender_user_id, receiver_user_id, amount, currency, transaction_status, transaction_timestamp, description')
          .in('receiver_user_id', userIds);

        const txMap = new Map();
        [...(sentTxns || []), ...(recvTxns || [])].forEach(t => {
          if (!txMap.has(t.transaction_id)) {
            txMap.set(t.transaction_id, t);
          }
        });

        const sortedTxns = Array.from(txMap.values()).sort((a, b) => 
          new Date(b.transaction_timestamp || b.created_at || 0) - new Date(a.transaction_timestamp || a.created_at || 0)
        );

        communityTransactions = sortedTxns.map(t => ({
          transaction_id: t.transaction_id,
          sender_account_id: userIdToAccountId[t.sender_user_id] || t.sender_user_id,
          sender_name: detailsMap[userIdToAccountId[t.sender_user_id]]?.full_name || userIdToAccountId[t.sender_user_id] || t.sender_user_id,
          receiver_account_id: userIdToAccountId[t.receiver_user_id] || t.receiver_user_id,
          receiver_name: detailsMap[userIdToAccountId[t.receiver_user_id]]?.full_name || userIdToAccountId[t.receiver_user_id] || t.receiver_user_id,
          amount: parseFloat(t.amount) || 0,
          currency: t.currency || 'INR',
          status: t.transaction_status || 'completed',
          timestamp: t.transaction_timestamp,
          description: t.description || 'Transfer'
        }));
      }

      return {
        postures: enrichedPostures,
        edges: ringEdges || [],
        transactions: communityTransactions
      };
    } catch (err) {
      console.error('[MMIE] getRingsForAccount error:', err.message);
      return { postures: [], edges: [] };
    }
  }
};

/**
 * Insider Threat Baseline & Employee Profile Repository
 * Manages employee behavioral baselines, operational metrics, and decision counters (transactions accepted/rejected per analyst)
 * Supports Supabase PostgreSQL with robust in-memory fallback.
 */

import { supabase } from '../../db/supabaseClient.js';

// Pre-seeded baseline profiles for all 10 centralized analysts / employees
const INITIAL_INSIDER_PROFILES = [
  {
    employee_id: 'ANL-001001',
    employee_name: 'Analyzer 01',
    email: 'analyzer1@gmail.com',
    role: 'Senior Fraud Investigator',
    department: 'Fraud Operations',
    authorized_device_details: 'Chrome 122 on Windows 11 Workstation',
    normal_working_time: '09:00 AM - 06:00 PM EST',
    normal_location: 'New York, US',
    normal_ip_address: '192.168.1.101',
    total_transactions_processed: 0,
    total_transactions_accepted: 0,
    total_transactions_rejected: 0,
    average_transaction_amount: 15000.00,
    maximum_transaction_amount: 50000.00,
    average_accounts_accessed_per_day: 12,
    maximum_accounts_accessed_per_day: 25,
    total_data_downloaded: '150 MB',
    total_data_exported: '25 MB',
    authorized_departments: '["Fraud Operations", "Risk Management"]',
    authorized_resources: '["Analyst Portal", "High Risk Sessions", "Baseline Engine"]'
  },
  {
    employee_id: 'ANL-001002',
    employee_name: 'Analyzer 02',
    email: 'analyzer2@gmail.com',
    role: 'SOC Risk Lead',
    department: 'Risk Intelligence',
    authorized_device_details: 'Safari on macOS Sonoma Workstation',
    normal_working_time: '08:00 AM - 05:00 PM EST',
    normal_location: 'New York, US',
    normal_ip_address: '192.168.1.102',
    total_transactions_processed: 0,
    total_transactions_accepted: 0,
    total_transactions_rejected: 0,
    average_transaction_amount: 18000.00,
    maximum_transaction_amount: 75000.00,
    average_accounts_accessed_per_day: 15,
    maximum_accounts_accessed_per_day: 30,
    total_data_downloaded: '210 MB',
    total_data_exported: '30 MB',
    authorized_departments: '["Risk Intelligence", "Cyber Defense"]',
    authorized_resources: '["Analyst Portal", "High Risk Sessions", "Threat Feeds"]'
  },
  {
    employee_id: 'ANL-001003',
    employee_name: 'Analyzer 03',
    email: 'analyzer3@gmail.com',
    role: 'Behavioral Fraud Specialist',
    department: 'Behavioral Analytics',
    authorized_device_details: 'Edge on Windows 11 Workstation',
    normal_working_time: '09:30 AM - 06:30 PM EST',
    normal_location: 'Chicago, US',
    normal_ip_address: '192.168.1.103',
    total_transactions_processed: 0,
    total_transactions_accepted: 0,
    total_transactions_rejected: 0,
    average_transaction_amount: 12000.00,
    maximum_transaction_amount: 40000.00,
    average_accounts_accessed_per_day: 10,
    maximum_accounts_accessed_per_day: 20,
    total_data_downloaded: '120 MB',
    total_data_exported: '15 MB',
    authorized_departments: '["Behavioral Analytics", "Fraud Operations"]',
    authorized_resources: '["Analyst Portal", "Telemetry Engine"]'
  },
  {
    employee_id: 'ANL-001004',
    employee_name: 'Analyzer 04',
    email: 'analyzer4@gmail.com',
    role: 'AML & Money Laundering Analyst',
    department: 'AML Compliance',
    authorized_device_details: 'Firefox on Linux Ubuntu Workstation',
    normal_working_time: '09:00 AM - 06:00 PM EST',
    normal_location: 'Charlotte, US',
    normal_ip_address: '192.168.1.104',
    total_transactions_processed: 0,
    total_transactions_accepted: 0,
    total_transactions_rejected: 0,
    average_transaction_amount: 25000.00,
    maximum_transaction_amount: 100000.00,
    average_accounts_accessed_per_day: 18,
    maximum_accounts_accessed_per_day: 35,
    total_data_downloaded: '300 MB',
    total_data_exported: '45 MB',
    authorized_departments: '["AML Compliance", "Legal"]',
    authorized_resources: '["Analyst Portal", "High Risk Sessions", "AML Audit"]'
  },
  {
    employee_id: 'ANL-001005',
    employee_name: 'Analyzer 05',
    email: 'analyzer5@gmail.com',
    role: 'Session Hijacking Investigator',
    department: 'Cyber Security',
    authorized_device_details: 'Chrome on macOS Sonoma Workstation',
    normal_working_time: '10:00 AM - 07:00 PM EST',
    normal_location: 'San Francisco, US',
    normal_ip_address: '192.168.1.105',
    total_transactions_processed: 0,
    total_transactions_accepted: 0,
    total_transactions_rejected: 0,
    average_transaction_amount: 14000.00,
    maximum_transaction_amount: 45000.00,
    average_accounts_accessed_per_day: 11,
    maximum_accounts_accessed_per_day: 22,
    total_data_downloaded: '175 MB',
    total_data_exported: '20 MB',
    authorized_departments: '["Cyber Security", "Fraud Operations"]',
    authorized_resources: '["Analyst Portal", "Session Tracker"]'
  },
  {
    employee_id: 'ANL-001006',
    employee_name: 'Analyzer 06',
    email: 'analyzer6@gmail.com',
    role: 'Cyber Risk Operations Officer',
    department: 'Risk Operations',
    authorized_device_details: 'Edge on Windows 11 Enterprise',
    normal_working_time: '08:30 AM - 05:30 PM EST',
    normal_location: 'Dallas, US',
    normal_ip_address: '192.168.1.106',
    total_transactions_processed: 0,
    total_transactions_accepted: 0,
    total_transactions_rejected: 0,
    average_transaction_amount: 16500.00,
    maximum_transaction_amount: 60000.00,
    average_accounts_accessed_per_day: 14,
    maximum_accounts_accessed_per_day: 28,
    total_data_downloaded: '190 MB',
    total_data_exported: '28 MB',
    authorized_departments: '["Risk Operations", "Fraud Operations"]',
    authorized_resources: '["Analyst Portal", "High Risk Sessions"]'
  },
  {
    employee_id: 'ANL-001007',
    employee_name: 'Analyzer 07',
    email: 'analyzer7@gmail.com',
    role: 'Identity & Authentication Specialist',
    department: 'Identity Security',
    authorized_device_details: 'Safari on macOS Sonoma Workstation',
    normal_working_time: '09:00 AM - 06:00 PM EST',
    normal_location: 'Boston, US',
    normal_ip_address: '192.168.1.107',
    total_transactions_processed: 0,
    total_transactions_accepted: 0,
    total_transactions_rejected: 0,
    average_transaction_amount: 13500.00,
    maximum_transaction_amount: 42000.00,
    average_accounts_accessed_per_day: 13,
    maximum_accounts_accessed_per_day: 24,
    total_data_downloaded: '160 MB',
    total_data_exported: '18 MB',
    authorized_departments: '["Identity Security", "IAM Team"]',
    authorized_resources: '["Analyst Portal", "Authentication Logs"]'
  },
  {
    employee_id: 'ANL-001008',
    employee_name: 'Analyzer 08',
    email: 'analyzer8@gmail.com',
    role: 'Forensic Audit Investigator',
    department: 'Internal Audit',
    authorized_device_details: 'Chrome on Windows 11 Enterprise',
    normal_working_time: '09:00 AM - 06:00 PM EST',
    normal_location: 'New York, US',
    normal_ip_address: '192.168.1.108',
    total_transactions_processed: 0,
    total_transactions_accepted: 0,
    total_transactions_rejected: 0,
    average_transaction_amount: 22000.00,
    maximum_transaction_amount: 90000.00,
    average_accounts_accessed_per_day: 20,
    maximum_accounts_accessed_per_day: 40,
    total_data_downloaded: '350 MB',
    total_data_exported: '50 MB',
    authorized_departments: '["Internal Audit", "Executive"]',
    authorized_resources: '["Analyst Portal", "Forensic Audit Log"]'
  },
  {
    employee_id: 'ANL-001009',
    employee_name: 'Analyzer 09',
    email: 'analyzer9@gmail.com',
    role: 'Risk Engine Rule Engineer',
    department: 'Risk Engineering',
    authorized_device_details: 'Firefox on Linux Fedora Workstation',
    normal_working_time: '10:00 AM - 07:00 PM EST',
    normal_location: 'Seattle, US',
    normal_ip_address: '192.168.1.109',
    total_transactions_processed: 0,
    total_transactions_accepted: 0,
    total_transactions_rejected: 0,
    average_transaction_amount: 11000.00,
    maximum_transaction_amount: 35000.00,
    average_accounts_accessed_per_day: 9,
    maximum_accounts_accessed_per_day: 18,
    total_data_downloaded: '140 MB',
    total_data_exported: '12 MB',
    authorized_departments: '["Risk Engineering", "Platform Dev"]',
    authorized_resources: '["Analyst Portal", "Risk Rules"]'
  },
  {
    employee_id: 'ANL-001010',
    employee_name: 'Analyzer 10',
    email: 'analyzer10@gmail.com',
    role: 'Chief Fraud Intelligence Analyst',
    department: 'Fraud Operations Command',
    authorized_device_details: 'Chrome on macOS M3 Max Workstation',
    normal_working_time: '08:00 AM - 06:00 PM EST',
    normal_location: 'New York, US',
    normal_ip_address: '192.168.1.110',
    total_transactions_processed: 0,
    total_transactions_accepted: 0,
    total_transactions_rejected: 0,
    average_transaction_amount: 30000.00,
    maximum_transaction_amount: 150000.00,
    average_accounts_accessed_per_day: 25,
    maximum_accounts_accessed_per_day: 50,
    total_data_downloaded: '500 MB',
    total_data_exported: '75 MB',
    authorized_departments: '["Executive Command", "Fraud Operations"]',
    authorized_resources: '["Analyst Portal", "Command Center", "Audit Feeds"]'
  }
];

class InsiderThreatRepository {
  constructor() {
    // In-memory fallback map for insider threat employee profiles
    this.memoryProfilesMap = new Map();
    INITIAL_INSIDER_PROFILES.forEach(p => {
      this.memoryProfilesMap.set(p.email.toLowerCase(), {
        ...p,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      });
      this.memoryProfilesMap.set(p.employee_id.toLowerCase(), this.memoryProfilesMap.get(p.email.toLowerCase()));
    });
  }

  /**
   * Get employee/analyst insider threat profile by email or ID
   */
  async getProfile(emailOrId) {
    if (!emailOrId) return null;
    const key = emailOrId.toLowerCase().trim();

    try {
      const { data, error } = await supabase
        .from('insider_threat_profiles')
        .select('*')
        .or(`email.eq.${emailOrId},employee_id.eq.${emailOrId}`)
        .maybeSingle();

      if (!error && data) {
        return data;
      }
    } catch (err) {
      // Fall through to memory store
    }

    return this.memoryProfilesMap.get(key) || null;
  }

  /**
   * Get all employee insider threat profiles
   */
  async getAllProfiles() {
    try {
      const { data, error } = await supabase
        .from('insider_threat_profiles')
        .select('*')
        .order('employee_id', { ascending: true });

      if (!error && data && data.length > 0) {
        return data;
      }
    } catch (err) {
      // Fall through to memory store
    }

    const uniqueProfiles = new Set(Array.from(this.memoryProfilesMap.values()));
    return Array.from(uniqueProfiles);
  }

  /**
   * Increment ACCEPTED transaction count for specific analyst
   */
  async incrementAcceptedTransaction(emailOrId) {
    const profile = await this.getProfile(emailOrId);
    if (!profile) return null;

    const updatedAccepted = (profile.total_transactions_accepted || 0) + 1;
    const updatedProcessed = (profile.total_transactions_processed || 0) + 1;
    const now = new Date().toISOString();

    try {
      const { data, error } = await supabase
        .from('insider_threat_profiles')
        .update({
          total_transactions_accepted: updatedAccepted,
          total_transactions_processed: updatedProcessed,
          updated_at: now
        })
        .eq('employee_id', profile.employee_id)
        .select()
        .single();

      if (!error && data) {
        // Keep in-memory store in sync
        this.updateMemoryStore(data);
        return data;
      }
    } catch (err) {
      // Fallback update memory store
    }

    profile.total_transactions_accepted = updatedAccepted;
    profile.total_transactions_processed = updatedProcessed;
    profile.updated_at = now;
    this.updateMemoryStore(profile);

    return profile;
  }

  /**
   * Increment REJECTED transaction count for specific analyst
   */
  async incrementRejectedTransaction(emailOrId) {
    const profile = await this.getProfile(emailOrId);
    if (!profile) return null;

    const updatedRejected = (profile.total_transactions_rejected || 0) + 1;
    const updatedProcessed = (profile.total_transactions_processed || 0) + 1;
    const now = new Date().toISOString();

    try {
      const { data, error } = await supabase
        .from('insider_threat_profiles')
        .update({
          total_transactions_rejected: updatedRejected,
          total_transactions_processed: updatedProcessed,
          updated_at: now
        })
        .eq('employee_id', profile.employee_id)
        .select()
        .single();

      if (!error && data) {
        // Keep in-memory store in sync
        this.updateMemoryStore(data);
        return data;
      }
    } catch (err) {
      // Fallback update memory store
    }

    profile.total_transactions_rejected = updatedRejected;
    profile.total_transactions_processed = updatedProcessed;
    profile.updated_at = now;
    this.updateMemoryStore(profile);

    return profile;
  }

  /**
   * Helper to update memory store
   */
  updateMemoryStore(profile) {
    this.memoryProfilesMap.set(profile.email.toLowerCase(), profile);
    this.memoryProfilesMap.set(profile.employee_id.toLowerCase(), profile);
  }

  /**
   * Save a completed review cycle
   */
  async saveReviewCycle(cycleData) {
    if (!cycleData) return null;
    inMemoryReviewCycles.set(cycleData.review_cycle_id, cycleData);

    try {
      const { data, error } = await supabase
        .from('review_cycles')
        .insert([cycleData])
        .select()
        .maybeSingle();

      if (!error && data) {
        inMemoryReviewCycles.set(data.review_cycle_id, data);
        return data;
      }
    } catch (e) {
      console.warn('Notice: review_cycles insert notice:', e.message);
    }
    return cycleData;
  }

  /**
   * Get all completed review cycles for an analyst
   */
  async getCompletedReviewCycles(analystEmail) {
    if (!analystEmail) return [];
    let dbCycles = [];
    try {
      const { data, error } = await supabase
        .from('review_cycles')
        .select('*')
        .eq('analyst_email', analystEmail)
        .order('created_at', { ascending: false });

      if (!error && data) dbCycles = data;
    } catch (e) {}

    const memCycles = Array.from(inMemoryReviewCycles.values())
      .filter(c => c.analyst_email.toLowerCase() === analystEmail.toLowerCase());

    const map = new Map();
    [...memCycles, ...dbCycles].forEach(c => map.set(c.review_cycle_id, c));

    return Array.from(map.values()).sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  }

  /**
   * Save an insider threat analysis result
   */
  async saveAnalysisResult(analysisData) {
    if (!analysisData) return null;
    inMemoryAnalyses.set(analysisData.analysis_id, analysisData);

    try {
      const { data, error } = await supabase
        .from('insider_threat_analyses')
        .insert([analysisData])
        .select()
        .maybeSingle();

      if (!error && data) {
        inMemoryAnalyses.set(data.analysis_id, data);
        return data;
      }
    } catch (e) {
      console.warn('Notice: insider_threat_analyses insert notice:', e.message);
    }
    return analysisData;
  }

  /**
   * Get all completed analyses for an analyst
   */
  async getAnalystAnalyses(analystEmail) {
    if (!analystEmail) return [];
    let dbAnalyses = [];
    try {
      const { data, error } = await supabase
        .from('insider_threat_analyses')
        .select('*')
        .eq('analyst_email', analystEmail)
        .order('created_at', { ascending: false });

      if (!error && data) dbAnalyses = data;
    } catch (e) {}

    const memAnalyses = Array.from(inMemoryAnalyses.values())
      .filter(a => a.analyst_email.toLowerCase() === analystEmail.toLowerCase());

    const map = new Map();
    [...memAnalyses, ...dbAnalyses].forEach(a => map.set(a.analysis_id, a));

    return Array.from(map.values()).sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  }

  /**
   * Get latest completed analysis for an analyst
   */
  async getLatestAnalysis(analystEmail) {
    const list = await this.getAnalystAnalyses(analystEmail);
    return list.length > 0 ? list[0] : null;
  }
}

// In-memory fallback stores for cycles & analyses
const inMemoryReviewCycles = new Map();
const inMemoryAnalyses = new Map();

export const insiderThreatRepository = new InsiderThreatRepository();


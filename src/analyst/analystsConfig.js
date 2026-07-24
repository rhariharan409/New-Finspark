/**
 * Centralized Multi-Analyst Configuration
 * Provides 10 realistic analyst accounts for FINSPARK Fraud Intelligence Operations Platform.
 */

export const CENTRALIZED_ANALYSTS = [
  {
    analyst_id: 'ANL-001001',
    name: 'Analyzer 01',
    email: 'analyzer1@gmail.com',
    role: 'Senior Fraud Investigator',
    clearance_level: 'Level 3 - Top Secret',
    status: 'active',
    avatar_color: '#2563eb'
  },
  {
    analyst_id: 'ANL-001002',
    name: 'Analyzer 02',
    email: 'analyzer2@gmail.com',
    role: 'SOC Risk Lead',
    clearance_level: 'Level 3 - Top Secret',
    status: 'active',
    avatar_color: '#059669'
  },
  {
    analyst_id: 'ANL-001003',
    name: 'Analyzer 03',
    email: 'analyzer3@gmail.com',
    role: 'Behavioral Fraud Specialist',
    clearance_level: 'Level 2 - Confidential',
    status: 'active',
    avatar_color: '#d97706'
  },
  {
    analyst_id: 'ANL-001004',
    name: 'Analyzer 04',
    email: 'analyzer4@gmail.com',
    role: 'AML & Money Laundering Analyst',
    clearance_level: 'Level 3 - Top Secret',
    status: 'active',
    avatar_color: '#7c3aed'
  },
  {
    analyst_id: 'ANL-001005',
    name: 'Analyzer 05',
    email: 'analyzer5@gmail.com',
    role: 'Session Hijacking Investigator',
    clearance_level: 'Level 2 - Confidential',
    status: 'active',
    avatar_color: '#ea580c'
  },
  {
    analyst_id: 'ANL-001006',
    name: 'Analyzer 06',
    email: 'analyzer6@gmail.com',
    role: 'Cyber Risk Operations Officer',
    clearance_level: 'Level 2 - Confidential',
    status: 'active',
    avatar_color: '#0891b2'
  },
  {
    analyst_id: 'ANL-001007',
    name: 'Analyzer 07',
    email: 'analyzer7@gmail.com',
    role: 'Identity & Authentication Specialist',
    clearance_level: 'Level 3 - Top Secret',
    status: 'active',
    avatar_color: '#4f46e5'
  },
  {
    analyst_id: 'ANL-001008',
    name: 'Analyzer 08',
    email: 'analyzer8@gmail.com',
    role: 'Forensic Audit Investigator',
    clearance_level: 'Level 3 - Top Secret',
    status: 'active',
    avatar_color: '#be185d'
  },
  {
    analyst_id: 'ANL-001009',
    name: 'Analyzer 09',
    email: 'analyzer9@gmail.com',
    role: 'Risk Engine Rule Engineer',
    clearance_level: 'Level 2 - Confidential',
    status: 'active',
    avatar_color: '#65a30d'
  },
  {
    analyst_id: 'ANL-001010',
    name: 'Analyzer 10',
    email: 'analyzer10@gmail.com',
    role: 'Chief Fraud Intelligence Analyst',
    clearance_level: 'Level 3 - Top Secret',
    status: 'active',
    avatar_color: '#dc2626'
  }
];

export function getAnalystByEmailOrId(identifier) {
  if (!identifier) return CENTRALIZED_ANALYSTS[0];
  const clean = String(identifier).trim().toLowerCase();
  return CENTRALIZED_ANALYSTS.find(a => 
    a.email.toLowerCase() === clean || a.analyst_id.toLowerCase() === clean
  ) || CENTRALIZED_ANALYSTS[0];
}

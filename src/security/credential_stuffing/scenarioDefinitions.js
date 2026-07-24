/**
 * Attack Scenario Definitions (Person 2: SK)
 * Realistic attack scenario definitions for attack simulation and replay testing.
 */

export const SCENARIO_DEFINITIONS = {
  CREDENTIAL_STUFFING_SPRAY: {
    name: 'Credential Stuffing — IP Spraying 8 Accounts',
    entity_id: '198.51.100.42',
    events: [
      {
        event_id: 'EVT_SPRAY_1',
        event_type: 'login',
        entity_id: 'USER_201',
        ip_address: '198.51.100.42',
        payload: {
          login_success: false,
          password_hash: 'a1b2c3d4e5f6a7b8',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
        }
      },
      {
        event_id: 'EVT_SPRAY_2',
        event_type: 'login',
        entity_id: 'USER_202',
        ip_address: '198.51.100.42',
        payload: {
          login_success: false,
          password_hash: 'b2c3d4e5f6a7b8c9',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
        }
      },
      {
        event_id: 'EVT_SPRAY_3',
        event_type: 'login',
        entity_id: 'USER_203',
        ip_address: '198.51.100.42',
        payload: {
          login_success: false,
          password_hash: 'c3d4e5f6a7b8c9d0',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
        }
      },
      {
        event_id: 'EVT_SPRAY_4',
        event_type: 'login',
        entity_id: 'USER_204',
        ip_address: '198.51.100.42',
        payload: {
          login_success: false,
          password_hash: 'd4e5f6a7b8c9d0e1',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
        }
      },
      {
        event_id: 'EVT_SPRAY_5',
        event_type: 'login',
        entity_id: 'USER_205',
        ip_address: '198.51.100.42',
        payload: {
          login_success: false,
          password_hash: 'e5f6a7b8c9d0e1f2',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
        }
      },
      {
        event_id: 'EVT_SPRAY_6',
        event_type: 'login',
        entity_id: 'USER_206',
        ip_address: '198.51.100.42',
        payload: {
          login_success: false,
          password_hash: 'f6a7b8c9d0e1f2a3',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
        }
      },
      {
        event_id: 'EVT_SPRAY_7',
        event_type: 'login',
        entity_id: 'USER_207',
        ip_address: '198.51.100.42',
        payload: {
          login_success: false,
          password_hash: 'a7b8c9d0e1f2a3b4',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
        }
      },
      {
        event_id: 'EVT_SPRAY_8',
        event_type: 'login',
        entity_id: 'USER_208',
        ip_address: '198.51.100.42',
        payload: {
          login_success: false,
          password_hash: 'b8c9d0e1f2a3b4c5',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
        }
      }
    ]
  },

  BRUTE_FORCE_SINGLE_ACCOUNT: {
    name: 'Brute Force — Targeting Admin Account',
    entity_id: 'USER_ADMIN_1',
    events: [
      {
        event_id: 'EVT_BRUTE_1',
        event_type: 'login',
        entity_id: 'USER_ADMIN_1',
        ip_address: '10.0.0.55',
        payload: {
          login_success: false,
          password_hash: '1a2b3c4d5e6f7a8b',
          user_agent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36'
        }
      },
      {
        event_id: 'EVT_BRUTE_2',
        event_type: 'login',
        entity_id: 'USER_ADMIN_1',
        ip_address: '10.0.0.55',
        payload: {
          login_success: false,
          password_hash: '2b3c4d5e6f7a8b9c',
          user_agent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36'
        }
      },
      {
        event_id: 'EVT_BRUTE_3',
        event_type: 'login',
        entity_id: 'USER_ADMIN_1',
        ip_address: '10.0.0.55',
        payload: {
          login_success: false,
          password_hash: '3c4d5e6f7a8b9c0d',
          user_agent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36'
        }
      },
      {
        event_id: 'EVT_BRUTE_4',
        event_type: 'login',
        entity_id: 'USER_ADMIN_1',
        ip_address: '10.0.0.55',
        payload: {
          login_success: false,
          password_hash: '4d5e6f7a8b9c0d1e',
          user_agent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36'
        }
      },
      {
        event_id: 'EVT_BRUTE_5',
        event_type: 'login',
        entity_id: 'USER_ADMIN_1',
        ip_address: '10.0.0.55',
        payload: {
          login_success: false,
          password_hash: '5e6f7a8b9c0d1e2f',
          user_agent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36'
        }
      },
      {
        event_id: 'EVT_BRUTE_6',
        event_type: 'login',
        entity_id: 'USER_ADMIN_1',
        ip_address: '10.0.0.55',
        payload: {
          login_success: false,
          password_hash: '6f7a8b9c0d1e2f3a',
          user_agent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36'
        }
      },
      {
        event_id: 'EVT_BRUTE_7',
        event_type: 'login',
        entity_id: 'USER_ADMIN_1',
        ip_address: '10.0.0.55',
        payload: {
          login_success: false,
          password_hash: '7a8b9c0d1e2f3a4b',
          user_agent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36'
        }
      }
    ]
  },

  PASSWORD_SPRAY_DISTRIBUTED: {
    name: 'Password Spraying — Same Password Across Accounts From Multiple IPs',
    entity_id: 'USER_301',
    events: [
      {
        event_id: 'EVT_PWSPRAY_1',
        event_type: 'login',
        entity_id: 'USER_301',
        ip_address: '203.0.113.10',
        payload: {
          login_success: false,
          password_hash: '5e884898da280471',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'
        }
      },
      {
        event_id: 'EVT_PWSPRAY_2',
        event_type: 'login',
        entity_id: 'USER_302',
        ip_address: '203.0.113.10',
        payload: {
          login_success: false,
          password_hash: '5e884898da280471',
          user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36'
        }
      },
      {
        event_id: 'EVT_PWSPRAY_3',
        event_type: 'login',
        entity_id: 'USER_303',
        ip_address: '203.0.113.11',
        payload: {
          login_success: false,
          password_hash: '5e884898da280471',
          user_agent: 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0'
        }
      },
      {
        event_id: 'EVT_PWSPRAY_4',
        event_type: 'login',
        entity_id: 'USER_304',
        ip_address: '203.0.113.11',
        payload: {
          login_success: false,
          password_hash: '5e884898da280471',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0'
        }
      },
      {
        event_id: 'EVT_PWSPRAY_5',
        event_type: 'login',
        entity_id: 'USER_305',
        ip_address: '203.0.113.12',
        payload: {
          login_success: false,
          password_hash: '5e884898da280471',
          user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 Safari/605.1.15'
        }
      },
      {
        event_id: 'EVT_PWSPRAY_6',
        event_type: 'login',
        entity_id: 'USER_306',
        ip_address: '203.0.113.12',
        payload: {
          login_success: false,
          password_hash: '5e884898da280471',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/120.0.2210.133'
        }
      }
    ]
  },

  HIGH_VELOCITY_SPIKE: {
    name: 'Velocity Spike — 25 Rapid Login Attempts in 60s from Single IP',
    entity_id: '198.51.100.99',
    events: Array.from({ length: 25 }, (_, i) => ({
      event_id: `EVT_VELOCITY_${i + 1}`,
      event_type: 'login',
      entity_id: `USER_VEL_${i + 1}`,
      ip_address: '198.51.100.99',
      payload: {
        login_success: false,
        password_hash: `unique_hash_vel_${i + 1}`,
        user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
      }
    }))
  },

  BOT_AUTOMATION_ATTACK: {
    name: 'Bot Automation Attack — Requests with Python User-Agent',
    entity_id: '198.51.100.77',
    events: [
      {
        event_id: 'EVT_BOT_1',
        event_type: 'login',
        entity_id: 'USER_BOT_1',
        ip_address: '198.51.100.77',
        payload: {
          login_success: false,
          password_hash: 'bot_hash_001',
          user_agent: 'python-requests/2.28.0'
        }
      }
    ]
  }
};

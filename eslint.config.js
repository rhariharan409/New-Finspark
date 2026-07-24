export default [
  {
    files: ['src/**/*.js', 'tests/**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        console: 'readonly',
        Map: 'readonly',
        Set: 'readonly',
        Date: 'readonly',
        Math: 'readonly',
        Number: 'readonly',
        Boolean: 'readonly',
        String: 'readonly',
        Array: 'readonly',
        Object: 'readonly',
        process: 'readonly'
      }
    },
    rules: {
      'no-unused-vars': 'warn',
      'no-undef': 'error'
    }
  }
];

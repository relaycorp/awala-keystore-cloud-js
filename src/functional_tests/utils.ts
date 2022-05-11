import { randomBytes } from 'crypto';

const todayString = new Date().toISOString().slice(0, 10).replace(/-/g, ''); // YYYYMMDD
export const TEST_RUN_ID = todayString + '-' + randomBytes(4).toString('hex');

import * as timing from '../lib/utils/timing';
import { mockSpy } from './jest';

export function mockSleep(): jest.SpyInstance {
  return mockSpy(jest.spyOn(timing, 'sleep'), () => undefined);
}

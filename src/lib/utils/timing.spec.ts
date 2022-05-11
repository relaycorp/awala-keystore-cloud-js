import { useFakeTimers } from '../../testUtils/jest';
import { sleep } from './timing';

useFakeTimers();

describe('sleep', () => {
  const TIMEOUT_MS = 60;

  test('Promise should not resolve before specified milliseconds have elapsed', async () => {
    let promiseResolved = false;

    sleep(TIMEOUT_MS).then(() => (promiseResolved = true));

    jest.advanceTimersByTime(TIMEOUT_MS - 1);
    expect(promiseResolved).toBeFalse();
    jest.runAllTimers();
  });

  test('Promise should resolve once specified milliseconds have elapsed', async () => {
    const sleepSecondsPromise = sleep(TIMEOUT_MS);

    jest.advanceTimersByTime(TIMEOUT_MS);
    await sleepSecondsPromise;
  });
});

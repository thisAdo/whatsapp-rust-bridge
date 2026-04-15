import assert from 'node:assert/strict';
import {
  describe as nodeDescribe,
  it as nodeIt,
  test as nodeTest,
  mock as nodeMock,
} from 'node:test';

function toComparable(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return Array.from(value);
  }

  if (Array.isArray(value)) {
    return value.map(toComparable);
  }

  if (value && typeof value === 'object') {
    const output = {};
    for (const key of Object.keys(value)) {
      output[key] = toComparable(value[key]);
    }
    return output;
  }

  return value;
}

function formatValue(value) {
  try {
    return JSON.stringify(toComparable(value));
  } catch {
    return String(value);
  }
}

function normalizeExpectedError(expected) {
  if (typeof expected === 'undefined') {
    return () => true;
  }

  if (typeof expected === 'string') {
    return error => String(error?.message ?? error).includes(expected);
  }

  if (expected instanceof RegExp) {
    return error => expected.test(String(error?.message ?? error));
  }

  if (typeof expected === 'function') {
    return error => error instanceof expected;
  }

  return error => String(error?.message ?? error).includes(String(expected));
}

function assertMatch(pass, message, negate) {
  if (negate ? pass : !pass) {
    assert.fail(message);
  }
}

function createMatchers(actual, negate = false) {
  return {
    get not() {
      return createMatchers(actual, !negate);
    },

    get rejects() {
      return {
        async toThrow(expected) {
          try {
            await actual;
            assert.fail('Expected promise to reject');
          } catch (error) {
            const match = normalizeExpectedError(expected)(error);
            assertMatch(match, `Expected rejection to match ${String(expected)}`, negate);
          }
        },
      };
    },

    toBe(expected) {
      const pass = Object.is(actual, expected);
      assertMatch(pass, `Expected ${formatValue(actual)} to be ${formatValue(expected)}`, negate);
    },

    toEqual(expected) {
      try {
        assert.deepStrictEqual(toComparable(actual), toComparable(expected));
        assertMatch(true, '', negate);
      } catch {
        assertMatch(false, `Expected ${formatValue(actual)} to equal ${formatValue(expected)}`, negate);
      }
    },

    toBeInstanceOf(expected) {
      const pass = actual instanceof expected;
      assertMatch(pass, `Expected value to be instance of ${expected?.name ?? expected}`, negate);
    },

    toBeGreaterThan(expected) {
      assertMatch(actual > expected, `Expected ${actual} to be greater than ${expected}`, negate);
    },

    toBeGreaterThanOrEqual(expected) {
      assertMatch(actual >= expected, `Expected ${actual} to be greater than or equal to ${expected}`, negate);
    },

    toBeLessThan(expected) {
      assertMatch(actual < expected, `Expected ${actual} to be less than ${expected}`, negate);
    },

    toBeLessThanOrEqual(expected) {
      assertMatch(actual <= expected, `Expected ${actual} to be less than or equal to ${expected}`, negate);
    },

    toBeDefined() {
      assertMatch(typeof actual !== 'undefined', 'Expected value to be defined', negate);
    },

    toBeUndefined() {
      assertMatch(typeof actual === 'undefined', 'Expected value to be undefined', negate);
    },

    toBeNull() {
      assertMatch(actual === null, 'Expected value to be null', negate);
    },

    toHaveLength(expected) {
      assertMatch(actual?.length === expected, `Expected length ${actual?.length} to be ${expected}`, negate);
    },

    toContain(expected) {
      const pass = typeof actual === 'string'
        ? actual.includes(expected)
        : Array.isArray(actual)
          ? actual.includes(expected)
          : false;
      assertMatch(pass, `Expected ${formatValue(actual)} to contain ${formatValue(expected)}`, negate);
    },

    toMatch(expected) {
      const pass = expected instanceof RegExp
        ? expected.test(String(actual))
        : String(actual).includes(String(expected));
      assertMatch(pass, `Expected ${formatValue(actual)} to match ${String(expected)}`, negate);
    },

    toHaveProperty(expected) {
      const pass = actual !== null && typeof actual === 'object' && expected in actual;
      assertMatch(pass, `Expected value to have property ${String(expected)}`, negate);
    },

    toBeCloseTo(expected, precision = 2) {
      const delta = Math.abs(Number(actual) - Number(expected));
      const threshold = 10 ** -precision;
      assertMatch(delta < threshold, `Expected ${actual} to be close to ${expected}`, negate);
    },

    toThrow(expected) {
      if (typeof actual !== 'function') {
        assert.fail('toThrow expects a function');
      }

      try {
        actual();
        assertMatch(false, 'Expected function to throw', negate);
      } catch (error) {
        const match = normalizeExpectedError(expected)(error);
        assertMatch(match, `Expected error to match ${String(expected)}`, negate);
      }
    },
  };
}

function wrapSuite(base) {
  const wrapped = (name, fn) => base(name, fn);
  wrapped.if = condition => (condition ? wrapped : (name, fn) => base.skip(name, fn));
  wrapped.skip = (name, fn) => base.skip(name, fn);
  wrapped.only = (name, fn) => base.only(name, fn);
  return wrapped;
}

export const describe = wrapSuite(nodeDescribe);
export const it = wrapSuite(nodeIt);
export const test = wrapSuite(nodeTest);
export const expect = actual => createMatchers(actual);
export const mock = implementation => {
  if (nodeMock?.fn) {
    return nodeMock.fn(implementation);
  }

  return (...args) => implementation?.(...args);
};
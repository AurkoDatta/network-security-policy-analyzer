import '@testing-library/jest-dom/vitest';

// Node's built-in localStorage global shadows jsdom's and throws without
// --localstorage-file configured, so tests get a deterministic in-memory
// stand-in instead.
class MemoryStorage implements Storage {
  private store = new Map<string, string>();

  get length(): number {
    return this.store.size;
  }

  clear(): void {
    this.store.clear();
  }

  getItem(key: string): string | null {
    return this.store.has(key) ? (this.store.get(key) as string) : null;
  }

  key(index: number): string | null {
    return Array.from(this.store.keys())[index] ?? null;
  }

  removeItem(key: string): void {
    this.store.delete(key);
  }

  setItem(key: string, value: string): void {
    this.store.set(key, value);
  }
}

Object.defineProperty(globalThis, 'localStorage', {
  value: new MemoryStorage(),
  writable: true,
  configurable: true,
});

// jsdom reports zero element dimensions, which stops Recharts'
// ResponsiveContainer from rendering its children. Stub a fixed non-zero
// size and polyfill ResizeObserver (unimplemented in jsdom) so chart
// components render in tests the same way they would in a real browser.
Object.defineProperty(HTMLElement.prototype, 'offsetWidth', { configurable: true, value: 500 });
Object.defineProperty(HTMLElement.prototype, 'offsetHeight', { configurable: true, value: 300 });
HTMLElement.prototype.getBoundingClientRect = () =>
  ({
    width: 500,
    height: 300,
    top: 0,
    left: 0,
    right: 500,
    bottom: 300,
    x: 0,
    y: 0,
    toJSON: () => undefined,
  }) as DOMRect;

class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}

globalThis.ResizeObserver = globalThis.ResizeObserver ?? (ResizeObserverStub as unknown as typeof ResizeObserver);

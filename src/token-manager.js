import crypto from 'node:crypto';

const ROTATION_MS = [5, 10, 15].map((m) => m * 60 * 1000);

export class TokenManager {
  constructor() {
    this.currentToken = this.#newToken();
    this.nextRotationAt = Date.now() + this.#pickRotationMs();
  }

  get token() {
    this.#maybeRotate();
    return this.currentToken;
  }

  validate(token) {
    this.#maybeRotate();
    return token === this.currentToken;
  }

  invalidateAndRotate() {
    this.currentToken = this.#newToken();
    this.nextRotationAt = Date.now() + this.#pickRotationMs();
    return this.currentToken;
  }

  #maybeRotate() {
    if (Date.now() >= this.nextRotationAt) {
      this.currentToken = this.#newToken();
      this.nextRotationAt = Date.now() + this.#pickRotationMs();
    }
  }

  #pickRotationMs() {
    return ROTATION_MS[Math.floor(Math.random() * ROTATION_MS.length)];
  }

  #newToken() {
    return crypto.randomBytes(24).toString('base64url');
  }
}

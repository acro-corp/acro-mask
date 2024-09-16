/**
 * Copyright (C) 2024 Acro Data Solutions, Inc.

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import {
  HIDE_REGEX,
  REMOVE_REGEX,
  SANITIZED_PII_WORDS_HIDE,
  SANITIZED_PII_WORDS_REMOVE,
} from "./constants";
import { Logger, LogLevel, MaskLevel } from "./types";

export class AcroMask {
  mask: string;
  logger: Logger;
  maskLevel: MaskLevel;
  _logger: Function | null;
  _logLevel: LogLevel;

  constructor(options?: {
    maskLevel?: MaskLevel;
    logger?: Function;
    logLevel?: LogLevel;
  }) {
    this._logLevel = options?.logLevel || LogLevel.warn;
    this._logger =
      options?.logger || (typeof console !== "undefined" ? console.log : null);

    this.logger = {
      off: this.log.bind(this, LogLevel.off),
      fatal: this.log.bind(this, LogLevel.fatal),
      error: this.log.bind(this, LogLevel.error),
      warn: this.log.bind(this, LogLevel.warn),
      info: this.log.bind(this, LogLevel.info),
      debug: this.log.bind(this, LogLevel.debug),
      trace: this.log.bind(this, LogLevel.trace),
      all: this.log.bind(this, LogLevel.all),
    };

    this.maskLevel = this.maskLevel || MaskLevel.REMOVE;
    this.mask = "*********";
  }

  private sanitizeString(keyName: string): string {
    return keyName
      .replace(/[^a-zA-Z0-9]/g, "")
      .toLowerCase()
      .trim();
  }

  private isJSONString(stringInQuestion: string) {
    try {
      // array or object
      return typeof JSON.parse(stringInQuestion) === "object";
    } catch (e) {
      return false;
    }
  }

  private isPIIKey(key: string, path: string): boolean {
    const sanitizedKey = this.sanitizeString(key);
    const piiWords =
      this.maskLevel === MaskLevel.HIDE
        ? SANITIZED_PII_WORDS_HIDE
        : SANITIZED_PII_WORDS_REMOVE;

    return !!piiWords.find((k) => {
      const match = sanitizedKey.includes(k);
      if (match) {
        this.logger.debug(`detected pii key on object path: ${path}`);
      }

      return match;
    });
  }

  private isPIIValue(value: string, path: string): boolean {
    const piiWords =
      this.maskLevel === MaskLevel.HIDE ? HIDE_REGEX : REMOVE_REGEX;
    const isPII = piiWords.some(({ regex, piiType, sanitize }) => {
      if (sanitize) {
        value = this.sanitizeString(value);
      }

      const match = regex.test(value);

      if (match) {
        this.logger.debug(
          `detected pii value on object path: ${path} type: ${piiType}`,
        );
      }
      return match;
    });
    return isPII;
  }

  maskPII(obj: Record<string, any> | Array<any>, currentPath = ""): Object {
    const recursivePIIMarker = (
      value: any,
      key: string | number,
      path: string,
    ): any | string => {
      const newPath =
        typeof key === "number"
          ? `${path}[${key}]`
          : `${path}${path ? "." : ""}${key}`;

      // Check for PII key names
      if (typeof key === "string" && this.isPIIKey(key, newPath)) {
        return this.mask;
      }

      // Check if its a stringified json before looking to see if it has pii
      if (typeof value === "string" && this.isJSONString(value)) {
        return JSON.stringify(this.maskPII(JSON.parse(value), newPath));
      }

      // Check for PII values
      if (typeof value === "string" && this.isPIIValue(value, newPath)) {
        return this.mask;
      }

      // Recursively process nested objects or arrays
      if (value && typeof value === "object") {
        return this.maskPII(value, newPath);
      }

      return value;
    };

    // Handle arrays
    if (Array.isArray(obj)) {
      const sanitizedArray = obj
        .map((item, index) => recursivePIIMarker(item, index, currentPath))
        .filter((item) => item !== undefined);
      return sanitizedArray;
    }

    // Handle objects
    if (obj && typeof obj === "object") {
      const sanitizedObj = Object.entries(obj).reduce(
        (acc: any, [key, value]) => {
          const processedValue = recursivePIIMarker(value, key, currentPath);
          if (processedValue !== undefined) {
            acc[key] = processedValue;
          }
          return acc;
        },
        {},
      );

      return sanitizedObj;
    }

    return obj;
  }

  /**
   * Logger function
   * @param {LogLevel} level
   * @param {string} message
   */
  log(level: LogLevel, message?: string, ...args: any) {
    if (
      level <= this._logLevel &&
      this._logger &&
      typeof this._logger === "function"
    ) {
      this._logger.apply(this, [
        `[${LogLevel[level]}] [@acro-sdk/store] ${message || ""}`,
        ...args,
      ]);
    }
  }
}

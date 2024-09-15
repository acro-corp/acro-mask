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
  CREDIT_CARD_REJEX,
  EMAIL_REJEX,
  IPV4_REJEX,
  IPV6_REJEX,
  LAT_LONG_REJEX,
  PASSWORD_REJEX,
  PHONE_NUMBER_REJEX,
  SANITIZED_PII_WORDS,
  SSN_REJEX,
} from "./constants";
import { Logger, LogLevel } from "./logger";

export class AcroMask {
  private mask: string;

  _logger: Function | null =
    typeof console !== "undefined" ? console.log : null;
  _logLevel: LogLevel = LogLevel.warn;

  logger: Logger;

  constructor(options?: { logger?: Function; logLevel?: LogLevel }) {
    if (options?.logLevel) {
      this._logLevel = options?.logLevel;
    }

    if (options?.logger) {
      this._logger = options?.logger;
    }

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

    this.mask = "*********";
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

  private sanitizeString(keyName: string): string {
    return keyName
      .replace(/[^a-zA-Z0-9]/g, "")
      .toLowerCase()
      .trim();
  }

  private isPIIKey(key: string): boolean {
    const sanitizedKey = this.sanitizeString(key);
    return !!SANITIZED_PII_WORDS.find((k) => k.includes(sanitizedKey));
  }

  private isPIIValue(value: string, path: string): boolean {
    const isPII = [
      { rejex: SSN_REJEX, piiType: "ssn" },
      { rejex: IPV4_REJEX, piiType: "ipv4" },
      { rejex: IPV6_REJEX, piiType: "ipv6" },
      { rejex: LAT_LONG_REJEX, piiType: "lat_long" },
      { rejex: PHONE_NUMBER_REJEX, piiType: "phone_number" },
      { rejex: PASSWORD_REJEX, piiType: "password" },
      { rejex: EMAIL_REJEX, piiType: "email" },
      {
        rejex: CREDIT_CARD_REJEX,
        piiType: "card_number",
        sanitize: true,
      },
    ].some(({ rejex, piiType, sanitize }) => {
      if (sanitize) {
        value = this.sanitizeString(value);
      }

      if (rejex.test(value)) {
        this.logger.debug(
          `detected pii on object path: ${path} type: ${piiType}`,
        );
        return true;
      }
      return false;
    });
    return isPII;
  }

  maskPII(obj: Record<string, any> | Array<any>, currentPath = ""): Object {
    const recursivePIIMarker = <V>(
      value: V,
      key: string | number,
      path: string,
    ): V | string => {
      const newPath =
        typeof key === "number"
          ? `${path}[${key}]`
          : `${path}${path ? "." : ""}${key}`;

      // Check for PII key names
      if (typeof key === "string" && this.isPIIKey(key)) {
        return this.mask;
      }

      // Check for PII values
      if (typeof value === "string" && this.isPIIValue(value, newPath)) {
        return this.mask;
      }

      // Recursively process nested objects or arrays
      if (value && typeof value === "object") {
        return this.maskPII(value, newPath) as V;
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
}

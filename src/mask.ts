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
  removeFields: string[];
  saveFields: string[];

  constructor(options?: {
    maskLevel?: MaskLevel;
    logger?: Function;
    logLevel?: LogLevel;
    removeFields?: string[];
    saveFields?: string[];
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

    this.maskLevel = options?.maskLevel || MaskLevel.REMOVE;
    this.mask = "*********";
    this.saveFields =
      options?.saveFields?.map((k) => this.sanitizeString(k)) || [];
    this.removeFields =
      options?.removeFields?.map((k) => this.sanitizeString(k)) || [];
  }

  /**
   * Masks any nested values in any objects or arrays.
   * @param obj The object that needs to have its data masked
   * @param currentPath The
   * @returns Masked Object
   */
  maskPII(obj: Record<string, any> | Array<any>) {
    return this.maskPIIHelper(obj);
  }

  /**
   * Recurisve masker
   */
  private maskPIIHelper(
    obj: Record<string, any> | Array<any>,
    currentPath = "",
  ): Object {
    const recursivePIIMarker = (
      value: any,
      key: string | number,
      path: string,
    ): any | string => {
      const newPath =
        typeof key === "number"
          ? `${path}[${key}]`
          : `${path}${path ? "." : ""}${key}`;

      if (typeof key === "string") {
        // Check save fields and return value if client wants to save
        if (this.saveFields.includes(this.sanitizeString(key))) {
          return value;
        }

        // Check remove fields and return mask if client wants to remove
        if (this.removeFields.includes(this.sanitizeString(key))) {
          return this.mask;
        }

        // Check for PII key names
        if (this.isPIIKey(key, path)) {
          return this.mask;
        }
      }

      if (typeof value === "string") {
        // Check if its a stringified json before looking to see if it has pii
        if (this.isJSONString(value)) {
          return JSON.stringify(this.maskPIIHelper(JSON.parse(value), newPath));
        }

        // Check for PII values
        if (this.isPIIValue(value, newPath)) {
          return this.mask;
        }
      }

      // Recursively process nested objects or arrays
      if (value && typeof value === "object") {
        return this.maskPIIHelper(value, newPath);
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
        this.logger.debug(`Acro detected pii key on object path: ${path}`);
      }

      return match;
    });
  }

  private isPIIValue(value: string, path: string): boolean {
    const piiWords =
      this.maskLevel === MaskLevel.HIDE ? HIDE_REGEX : REMOVE_REGEX;
    const isPII = piiWords.some(({ regex, piiType, sanitize }) => {
      const match = regex.test(sanitize ? this.sanitizeString(value) : value);

      if (match) {
        this.logger.debug(
          `Acro detected pii value on object path: ${path} type: ${piiType}`,
        );
      }
      return match;
    });
    return isPII;
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

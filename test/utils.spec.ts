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

import { describe, expect, test } from "vitest";
import { AcroMask, LogLevel } from "../src";

const piiMasker = new AcroMask({ logLevel: LogLevel.debug });

describe("piiMasker.maskPII()", () => {
  test("masks sensitive keys from a simple object", () => {
    const input = {
      name: "John Doe",
      email: "john.doe@example.com",
      password: "P@ssw0rd123!",
      address: "123 Main St, Anytown, USA",
    };
    expect(piiMasker.maskPII(input)).deep.equal({
      address: "*********",
      email: "*********",
      name: "*********",
      password: "*********",
    });
  });

  test("circular object", () => {
    type Node = {
      value: number;
      next?: Node;
    };

    const node1: Node = { value: 1 };
    const node2: Node = { value: 2 };
    const node3: Node = { value: 3 };

    // Creating circular references
    node1.next = node2;
    node2.next = node3;
    node3.next = node1;
    try {
      piiMasker.maskPII(node1);
    } catch (e) {
      expect(e.message).deep.equal("Maximum call stack size exceeded");
    }
  });

  test("masks sensitive keys from a nested object", () => {
    const input = {
      user: {
        personalInfo: {
          ssn: "123-45-6789",
          creditCard: "4111-1111-1111-1111",
        },
        contactInfo: {
          phone: "+1 (555) 123-4567",
          email: "jane.smith@example.com",
        },
      },
      metadata: {
        location: {
          lat: 40.7128,
          long: -74.006,
        },
      },
    };
    expect(piiMasker.maskPII(input)).deep.equal({
      user: {
        personalInfo: {
          ssn: "*********",
          creditCard: "*********",
        },
        contactInfo: {
          phone: "*********",
          email: "*********",
        },
      },
      metadata: {
        location: "*********",
      },
    });
  });

  test("masks sensitive keys in an array of objects", () => {
    const input = [
      { name: "Alice", email: "alice@example.com" },
      { name: "Bob", phone: "555-0123" },
      { name: "Charlie", ssn: "987-65-4321" },
    ];
    expect(piiMasker.maskPII(input)).deep.equal([
      {
        name: "*********",
        email: "*********",
      },
      {
        name: "*********",
        phone: "*********",
      },
      {
        name: "*********",
        ssn: "*********",
      },
    ]);
  });

  test("masks sensitive keys in objects with arrays", () => {
    const input = {
      passwords: ["qwerty123!", "P@ssw0rd", "SecurePass123!"],
      coordinates: [
        [40.7128, -74.006],
        [34.0522, -118.2437],
      ],
    };
    // qwerty123! needs uppercase to be a good password, not my fault—skill issue!
    expect(piiMasker.maskPII(input)).deep.equal({
      passwords: ["qwerty123!", "*********", "*********"],
      coordinates: "*********",
    });
  });

  test("masks sensitive data in a complex nested structure", () => {
    const input = {
      level1: {
        level2: [
          {
            level3: {
              user: { email: "nested@example.com", password: "nestedPass123!" },
              location: [51.5074, -0.1278],
            },
          },
        ],
      },
    };

    expect(piiMasker.maskPII(input)).deep.equal({
      level1: {
        level2: [
          {
            level3: {
              user: {
                email: "*********",
                password: "*********",
              },
              location: "*********",
            },
          },
        ],
      },
    });
  });

  test("handles mixed data types properly", () => {
    const input = {
      text: "Some non-sensitive text",
      number: 42,
      badpassword: "password123",
      nested: { email: "test@example.com" },
      array: [1, 2, { ssn: "111-22-3333" }],
    };

    expect(piiMasker.maskPII(input)).deep.equal({
      text: "Some non-sensitive text",
      number: "*********",
      // Skill issue again—see the first one
      badpassword: "password123",
      nested: {
        email: "*********",
      },
      array: [
        1,
        2,
        {
          ssn: "*********",
        },
      ],
    });
  });

  test("doesn't touch non-sensitive data", () => {
    const input = {
      name: "Public Figure",
      occupation: "Politician",
      email: "contact@government.com",
    };
    expect(piiMasker.maskPII(input)).deep.equal({
      name: "*********",
      occupation: "Politician",
      email: "*********",
    });
  });

  test("handles empty objects and arrays gracefully", () => {
    const input = {
      emptyObject: {},
      emptyArray: [],
      nestedEmpty: { empty: {} },
    };
    expect(piiMasker.maskPII(input)).deep.equal({
      emptyObject: {},
      emptyArray: [],
      nestedEmpty: {
        empty: {},
      },
    });
  });

  test("properly masks credit card numbers", () => {
    const input = {
      visa: "4111 1111 1111 1111",
      mastercard: "5555-5555-5555-4444",
      amex: "371449635398431",
    };
    expect(piiMasker.maskPII(input)).deep.equal({
      visa: "*********",
      mastercard: "*********",
      amex: "*********",
    });
  });

  test("accurately identifies and masks good passwords", () => {
    const input = {
      weak: "password123",
      strong: "P@ssw0rd!23",
      veryStrong: "Tr0ub4dor&3",
    };
    expect(piiMasker.maskPII(input)).deep.equal({
      // Skill issue—refer to the first one
      weak: "password123",
      strong: "*********",
      veryStrong: "*********",
    });
  });
});

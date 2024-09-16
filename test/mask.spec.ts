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
import { AcroMask } from "../src";
import { LogLevel, MaskLevel } from "../src/types";

describe("piiMasker.maskPII()", () => {
  describe("key masking tests -- mask level remove (default)", () => {
    const piiMasker = new AcroMask({ logLevel: LogLevel.debug });

    test("masks all specified keys", () => {
      const input = {
        password: "mySecretPassword",
        creds: "myCreds",
        jwt: "myJwtToken",
        jsonwebtoken: "myJsonWebToken",
        auth: "myAuth",
        pwd: "myPwd",
        apikey: "myApiKey",
        credential: "myCredential",
        secret: "mySecret",
        accesstoken: "myAccessToken",
        bearertoken: "myBearerToken",
        privatekey: "myPrivateKey",
        certificate: "myCertificate",
        ssn: "123-45-6789",
        socialsecuritynumber: "987-65-4320",
        creditcardnumber: "4111-1111-1111-1111",
        creditcard: "4111-1111-1111-1111",
        cvc: "123",
        ccnumber: "4111-1111-1111-1111",
        cardnumber: "4111-1111-1111-1111",
        bankaccountnumber: "123456789",
        routingnumber: "987654321",
        bankaccount: "123456789",
        driverslicense: "D1234567",
        passportnumber: "P12345678",
        medicalrecordnumber: "MRN123456",
        mrn: "MRN123456",
        insurancenumber: "INS123456",
        taxid: "TAX123456",
      };

      expect(piiMasker.maskPII(input)).deep.equal({
        password: "*********",
        creds: "*********",
        jwt: "*********",
        jsonwebtoken: "*********",
        auth: "*********",
        pwd: "*********",
        apikey: "*********",
        credential: "*********",
        secret: "*********",
        accesstoken: "*********",
        bearertoken: "*********",
        privatekey: "*********",
        certificate: "*********",
        ssn: "*********",
        socialsecuritynumber: "*********",
        creditcardnumber: "*********",
        creditcard: "*********",
        cvc: "*********",
        ccnumber: "*********",
        cardnumber: "*********",
        bankaccountnumber: "*********",
        routingnumber: "*********",
        bankaccount: "*********",
        driverslicense: "*********",
        passportnumber: "*********",
        medicalrecordnumber: "*********",
        mrn: "*********",
        insurancenumber: "*********",
        taxid: "*********",
      });
    });

    test("masks keys that include specified keys as substrings", () => {
      const input = {
        secretApiKey: "mySecretApiKey",
        userPassword: "mySecretPassword",
        apiKey: "myApiKey",
        userCreds: "myCreds",
        jwtToken: "myJwtToken",
        authInfo: {
          auth: "myAuth",
          pwd: "myPwd",
        },
        sensitiveData: {
          ssn: "123-45-6789",
          creditCardInfo: {
            creditCard: "4111-1111-1111-1111",
            cvc: "123",
          },
        },
        personalInfo: {
          driversLicense: "D1234567",
          passportNumber: "P12345678",
        },
        financialInfo: {
          bankAccount: {
            bankAccountNumber: "123456789",
            routingNumber: "987654321",
          },
        },
        additionalKeys: {
          apiKeyForService: "myApiKeyForService",
          secretKey: "mySecretKey",
        },
      };

      expect(piiMasker.maskPII(input)).deep.equal({
        secretApiKey: "*********",
        userPassword: "*********",
        apiKey: "*********",
        userCreds: "*********",
        jwtToken: "*********",
        authInfo: "*********",
        sensitiveData: {
          ssn: "*********",
          creditCardInfo: "*********",
        },
        personalInfo: {
          driversLicense: "*********",
          passportNumber: "*********",
        },
        financialInfo: {
          bankAccount: "*********",
        },
        additionalKeys: {
          apiKeyForService: "*********",
          secretKey: "*********",
        },
      });
    });
  });

  describe("key masking tests -- mask level hide", () => {
    const piiMasker = new AcroMask({
      logLevel: LogLevel.debug,
      maskLevel: MaskLevel.HIDE,
    });

    test("masks all specified keys", () => {
      const input = {
        password: "mySecretPassword",
        creds: "myCreds",
        jwt: "myJwtToken",
        jsonwebtoken: "myJsonWebToken",
        auth: "myAuth",
        pwd: "myPwd",
        apikey: "myApiKey",
        credential: "myCredential",
        secret: "mySecret",
        accesstoken: "myAccessToken",
        bearertoken: "myBearerToken",
        privatekey: "myPrivateKey",
        certificate: "myCertificate",
        ssn: "123-45-6789",
        socialsecuritynumber: "987-65-4320",
        creditcardnumber: "4111-1111-1111-1111",
        creditcard: "4111-1111-1111-1111",
        cvc: "123",
        ccnumber: "4111-1111-1111-1111",
        cardnumber: "4111-1111-1111-1111",
        bankaccountnumber: "123456789",
        routingnumber: "987654321",
        bankaccount: "123456789",
        driverslicense: "D1234567",
        passportnumber: "P12345678",
        medicalrecordnumber: "MRN123456",
        mrn: "MRN123456",
        insurancenumber: "INS123456",
        taxid: "TAX123456",
        // HIDE KEYS
        firstname: "John",
        fullname: "John Doe",
        preferredName: "Johnny",
        contact: "john.doe@example.com",
        legalName: "Johnathan Doe",
        lastname: "Doe",
        email: "john.doe@example.com",
        emailaddress: "john.doe@example.com",
        phone: "123-456-7890",
        phonenumber: "123-456-7890",
        mobilenumber: "123-456-7890",
        coordinates: "40.7128,-74.0060",
        location: "New York",
        latitude: "40.7128",
        longitude: "-74.0060",
        address: "123 Main St, Anytown, USA",
        zipcode: "10001",
        country: "USA",
        county: "New York",
        streetaddress: "123 Main St",
        city: "New York",
        postalcode: "10001",
      };

      expect(piiMasker.maskPII(input)).deep.equal({
        password: "*********",
        creds: "*********",
        jwt: "*********",
        jsonwebtoken: "*********",
        auth: "*********",
        pwd: "*********",
        apikey: "*********",
        credential: "*********",
        secret: "*********",
        accesstoken: "*********",
        bearertoken: "*********",
        privatekey: "*********",
        certificate: "*********",
        ssn: "*********",
        socialsecuritynumber: "*********",
        creditcardnumber: "*********",
        creditcard: "*********",
        cvc: "*********",
        ccnumber: "*********",
        cardnumber: "*********",
        bankaccountnumber: "*********",
        routingnumber: "*********",
        bankaccount: "*********",
        driverslicense: "*********",
        passportnumber: "*********",
        medicalrecordnumber: "*********",
        mrn: "*********",
        insurancenumber: "*********",
        taxid: "*********",
        // HIDE KEYS
        firstname: "*********",
        fullname: "*********",
        preferredName: "*********",
        contact: "*********",
        legalName: "*********",
        lastname: "*********",
        email: "*********",
        emailaddress: "*********",
        phone: "*********",
        phonenumber: "*********",
        mobilenumber: "*********",
        coordinates: "*********",
        location: "*********",
        latitude: "*********",
        longitude: "*********",
        address: "*********",
        zipcode: "*********",
        country: "*********",
        county: "*********",
        streetaddress: "*********",
        city: "*********",
        postalcode: "*********",
      });
    });

    test("masks keys that include specified keys as substrings", () => {
      const input = {
        secretApiKey: "mySecretApiKey",
        userPassword: "mySecretPassword",
        apiKey: "myApiKey",
        userCreds: "myCreds",
        jwtToken: "myJwtToken",
        authInfo: {
          auth: "myAuth",
          pwd: "myPwd",
        },
        sensitiveData: {
          ssn: "123-45-6789",
          creditCardInfo: {
            creditCard: "4111-1111-1111-1111",
            cvc: "123",
          },
        },
        personalInfo: {
          driversLicense: "D1234567",
          passportNumber: "P12345678",
        },
        financialInfo: {
          bankAccount: {
            bankAccountNumber: "123456789",
            routingNumber: "987654321",
          },
        },
        additionalKeys: {
          apiKeyForService: "myApiKeyForService",
          secretKey: "mySecretKey",
        },
        // HIDE KEYS
        firstName1: "John",
        fullName1: "John Doe",
        contactInfo: "john.doe@example.com",
        emailAddr: "john.doe@example.com",
        phoneNum: "123-456-7890",
        locationCity: "New York",
        addressFull: "123 Main St, Anytown, USA",
      };

      expect(piiMasker.maskPII(input)).deep.equal({
        secretApiKey: "*********",
        userPassword: "*********",
        apiKey: "*********",
        userCreds: "*********",
        jwtToken: "*********",
        authInfo: "*********",
        sensitiveData: {
          ssn: "*********",
          creditCardInfo: "*********",
        },
        personalInfo: {
          driversLicense: "*********",
          passportNumber: "*********",
        },
        financialInfo: {
          bankAccount: "*********",
        },
        additionalKeys: {
          apiKeyForService: "*********",
          secretKey: "*********",
        },
        // HIDE KEYS
        firstName1: "*********",
        fullName1: "*********",
        contactInfo: "*********",
        emailAddr: "*********",
        phoneNum: "*********",
        locationCity: "*********",
        addressFull: "*********",
      });
    });
  });

  describe("value masking tests -- mask level hide", () => {
    const piiMasker = new AcroMask({
      logLevel: LogLevel.debug,
      maskLevel: MaskLevel.HIDE,
    });

    test("masks phone numbers", () => {
      const input = {
        usa: "4089212222",
        usaAreaCode: "14089212605",
        uaeAreaCode: "+9711998222",
        formatted: "(408) 408-2722",
      };
      expect(piiMasker.maskPII(input)).deep.equal({
        usa: "*********",
        usaAreaCode: "*********",
        uaeAreaCode: "*********",
        formatted: "*********",
      });
    });

    test("masks latitude and longitude", () => {
      const input = {
        randomKey: "40.7128,-74.0060",
      };
      expect(piiMasker.maskPII(input)).deep.equal({
        randomKey: "*********",
      });
    });

    test("masks passwords", () => {
      const input = {
        randomKey: "P@ssw0rd123!",
      };
      expect(piiMasker.maskPII(input)).deep.equal({
        randomKey: "*********",
      });
    });

    test("masks emails", () => {
      const input = {
        randomKey: "john.doe@example.com",
      };
      expect(piiMasker.maskPII(input)).deep.equal({
        randomKey: "*********",
      });
    });

    test("masks social security numbers", () => {
      const input = {
        randomKey: "123-45-6789",
      };
      expect(piiMasker.maskPII(input)).deep.equal({
        randomKey: "*********",
      });
    });

    test("masks IPv4 addresses", () => {
      const input = {
        randomKey: "192.168.1.1",
      };
      expect(piiMasker.maskPII(input)).deep.equal({
        randomKey: "*********",
      });
    });

    test("masks IPv6 addresses", () => {
      const input = {
        randomKey: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
      };
      expect(piiMasker.maskPII(input)).deep.equal({
        randomKey: "*********",
      });
    });

    test("masks credit card numbers", () => {
      const input = {
        randomKey: "4111 1111 1111 1111",
        randomKeyNoSpace: "4111111111111111",
      };
      expect(piiMasker.maskPII(input)).deep.equal({
        randomKey: "*********",
        randomKeyNoSpace: "*********",
      });
    });

    test("masks private keys", () => {
      const input = {
        key: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAAOCAQ8A",
        rsa: "-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAAOCAQ8A",
      };
      expect(piiMasker.maskPII(input)).deep.equal({
        key: "*********",
        rsa: "*********",
      });
    });
  });

  describe("value masking tests -- mask level remove", () => {
    const piiMasker = new AcroMask({
      logLevel: LogLevel.debug,
      maskLevel: MaskLevel.REMOVE,
    });

    test("masks request headers", () => {
      const input = {
        Authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        Cookie: "sessionId=abc123; trackingId=xyz789;",
        Cookies: "sessionId=abc123; trackingId=xyz789;",
        "X-User-ID": "12345",
        "X-Email": "user@example.com",
        "X-Phone-Number": "+1234567890",
        "X-Forwarded-For": "192.168.1.1",
        "X-Real-IP": "192.168.1.1",
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
        Referer: "https://example.com/login?email=user%40example.com",
        "Content-Type": "application/json",
        Accept: "application/json",
        "X-Session-ID": "sess_456789",
        "X-Device-ID": "device_98765",
        "X-Client-ID": "client_54321",
        "Accept-Language": "en-US,en;q=0.9",
        Host: "api.example.com",
        Connection: "keep-alive",
      };
      expect(piiMasker.maskPII(input)).deep.equal({
        Accept: "application/json",
        "Accept-Language": "en-US,en;q=0.9",
        Authorization: "*********",
        Connection: "keep-alive",
        "Content-Type": "application/json",
        Cookie: "*********",
        Cookies: "*********",
        Host: "api.example.com",
        Referer: "https://example.com/login?email=user%40example.com",
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
        "X-Client-ID": "client_54321",
        "X-Device-ID": "device_98765",
        "X-Email": "user@example.com",
        "X-Forwarded-For": "192.168.1.1",
        "X-Phone-Number": "+1234567890",
        "X-Real-IP": "*********",
        "X-Session-ID": "sess_456789",
        "X-User-ID": "12345",
      });
    });

    test("does not mask phone numbers", () => {
      const input = {
        usa: "4089212222",
        usaAreaCode: "14089212605",
        uaeAreaCode: "+9711998222",
        formatted: "(408) 408-2722",
      };
      expect(piiMasker.maskPII(input)).deep.equal({
        usa: "4089212222",
        usaAreaCode: "14089212605",
        uaeAreaCode: "+9711998222",
        formatted: "(408) 408-2722",
      });
    });

    test("does not mask latitude and longitude", () => {
      const input = {
        randomKey: "40.7128,-74.0060",
      };
      expect(piiMasker.maskPII(input)).deep.equal({
        randomKey: "40.7128,-74.0060",
      });
    });

    test("does not mask passwords", () => {
      const input = {
        randomKey: "P@ssw0rd123!",
      };
      expect(piiMasker.maskPII(input)).deep.equal({
        randomKey: "P@ssw0rd123!",
      });
    });

    test("does not mask emails", () => {
      const input = {
        randomKey: "john.doe@example.com",
      };
      expect(piiMasker.maskPII(input)).deep.equal({
        randomKey: "john.doe@example.com",
      });
    });

    test("masks social security numbers", () => {
      const input = {
        randomKey: "123-45-6789",
      };
      expect(piiMasker.maskPII(input)).deep.equal({
        randomKey: "*********",
      });
    });

    test("does not mask IPv4 addresses", () => {
      const input = {
        randomKey: "192.168.1.1",
      };
      expect(piiMasker.maskPII(input)).deep.equal({
        randomKey: "192.168.1.1",
      });
    });

    test("does not mask IPv6 addresses", () => {
      const input = {
        randomKey: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
      };
      expect(piiMasker.maskPII(input)).deep.equal({
        randomKey: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
      });
    });

    test("does not mask credit card numbers", () => {
      const input = {
        randomKey: "4111 1111 1111 1111",
        randomKeyNoSpace: "4111111111111111",
      };
      expect(piiMasker.maskPII(input)).deep.equal({
        randomKey: "4111 1111 1111 1111",
        randomKeyNoSpace: "4111111111111111",
      });
    });

    test("masks private keys", () => {
      const input = {
        key: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAAOCAQ8A",
        rsa: "-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAAOCAQ8A",
      };
      expect(piiMasker.maskPII(input)).deep.equal({
        key: "*********",
        rsa: "*********",
      });
    });
  });

  describe("edge cases", () => {
    const piiMasker = new AcroMask({
      logLevel: LogLevel.debug,
      maskLevel: MaskLevel.HIDE,
    });

    test("does not mask a uuid", () => {
      const input = {
        id: "b545ec39-7c49-4991-91f1-ecc521eba456",
      };

      expect(piiMasker.maskPII(input)).deep.equal({
        id: "b545ec39-7c49-4991-91f1-ecc521eba456",
      });
    });

    test("does not mask seconds since epoch", () => {
      const input = {
        svixtimestamp: "1726270596",
      };

      expect(piiMasker.maskPII(input)).deep.equal({
        svixtimestamp: "1726270596",
      });
    });

    test("dies on circular object", () => {
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

    test("masks sensitive keys in an array of objects", () => {
      const input = [
        { email: "alice@example.com" },
        { phone: "555-0123" },
        { ssn: "987-65-4321" },
      ];
      expect(piiMasker.maskPII(input)).deep.equal([
        {
          email: "*********",
        },
        {
          phone: "*********",
        },
        {
          ssn: "*********",
        },
      ]);
    });

    test("masks sensitive data in a complex nested structure", () => {
      const input = {
        level1: {
          level2: [
            {
              level3: {
                user: {
                  email: "nested@example.com",
                  password: "nestedPass123!",
                },
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

    test("masks a stupid object", () => {
      const input = {
        text: "Some non-sensitive text",
        number: 42,
        badpassword: "password123",
        nested: { email: "test@example.com" },
        array: [1, 2, { ssn: "111-22-3333" }],
      };

      expect(piiMasker.maskPII(input)).deep.equal({
        text: "Some non-sensitive text",
        number: 42,
        badpassword: "*********",
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

    test("does not mask a password because the key wasn't classified as pii and its weak", () => {
      const input = {
        badpass: "password123",
      };

      expect(piiMasker.maskPII(input)).deep.equal({
        badpass: "password123",
      });
    });

    test("masks a strong password even tho the key wasn't classified as pii", () => {
      const input = {
        udontknowlol: "7leavesBobatEA!!",
      };

      expect(piiMasker.maskPII(input)).deep.equal({
        udontknowlol: "*********",
      });
    });

    test("empty objects and arrays", () => {
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

    test("masks keys in stringified json", () => {
      const input = {
        agents: JSON.stringify([
          {
            type: "user",
            id: "user_webjwejewbweBJDDDW",
            meta: {
              ip: "193.142.146.111",
              userAgent:
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
              clerkUserId: "user_webjwejewbweBJDDDW",
            },
          },
        ]),
      };
      expect(piiMasker.maskPII(input)).deep.equal({
        agents: JSON.stringify([
          {
            type: "user",
            id: "user_webjwejewbweBJDDDW",
            meta: {
              ip: "*********",
              userAgent: "*********",
              clerkUserId: "user_webjwejewbweBJDDDW",
            },
          },
        ]),
      });
    });
  });

  describe("removeFields saveFields", () => {
    const piiMasker = new AcroMask({
      maskLevel: MaskLevel.HIDE,
      removeFields: ["pwn", "iDontListenToRules", "s"],
      saveFields: ["secret", "userAgent"],
    });

    test("overrides", () => {
      const input = {
        secret: "istolecharleslambo",
        pwn: "y me",
        idontlistentorules:
          "this shud be masked even tho the removed field is not formatted correctly",
        ssssss: "should not be masked",
        headers: {
          "user-agent": "blah()()()()()BLAH",
        },
      };

      expect(piiMasker.maskPII(input)).deep.equal({
        secret: "istolecharleslambo",
        pwn: "*********",
        idontlistentorules: "*********",
        ssssss: "should not be masked",
        headers: {
          "user-agent": "blah()()()()()BLAH",
        },
      });
    });
  });
});

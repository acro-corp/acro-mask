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

const LAT_LONG_REGEX = /^((\-?|\+?)?\d+(\.\d+)?),\s*((\-?|\+?)?\d+(\.\d+)?)$/;
const PASSWORD_REGEX =
  /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-_]).{8,}$/;
const EMAIL_REGEX =
  /(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/;
const SSN_REGEX = /^(?!0{3})(?!6{3})[0-8]\d{2}-(?!0{2})\d{2}-(?!0{4})\d{4}$/;
const PHONE_NUMBER_REGEX =
  /^\+?1?\s?\(?([2-9]{1}[0-9]{2})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})$/;
const IPV4_REGEX =
  /(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}/;
const IPV6_REGEX =
  /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/;
const CREDIT_CARD_REGEX = /\b\d{15,}\b/;
const PRIVATE_KEYS_REGEX = /\s*(\bBEGIN\b).*(PRIVATE KEY\b)\s*/gm;

export const REMOVE_REGEX: {
  regex: RegExp;
  piiType: string;
  sanitize?: boolean;
}[] = [
  { regex: PRIVATE_KEYS_REGEX, piiType: "privatekey" },
  { regex: SSN_REGEX, piiType: "ssn" },
];
export const HIDE_REGEX: {
  regex: RegExp;
  piiType: string;
  sanitize?: boolean;
}[] = [
  { regex: IPV4_REGEX, piiType: "ipv4" },
  { regex: IPV6_REGEX, piiType: "ipv6" },
  { regex: LAT_LONG_REGEX, piiType: "lat_long" },
  { regex: PHONE_NUMBER_REGEX, piiType: "phone_number" },
  { regex: PASSWORD_REGEX, piiType: "password" },
  { regex: EMAIL_REGEX, piiType: "email" },
  {
    regex: CREDIT_CARD_REGEX,
    piiType: "card_number",
    sanitize: true,
  },
  // hide should include remove just incase
  ...REMOVE_REGEX,
];

// WORDS MUST BE SANITIZED BEFORE USING THIS
export const SANITIZED_PII_WORDS_REMOVE = [
  // secrets tokens etc
  "password",
  "creds",
  "jwt",
  "jsonwebtoken",
  "auth",
  "pwd",
  "apikey",
  "credential",
  "secret",
  "accesstoken",
  "bearertoken",
  "privatekey",
  "certificate",
  // personal info
  "ssn",
  "socialsecuritynumber",
  "creditcardnumber",
  "creditcard",
  "cvc",
  "ccnumber",
  "cardnumber",
  "bankaccountnumber",
  "routingnumber",
  "bankaccount",
  "driverslicense",
  "passportnumber",
  "medicalrecordnumber",
  "mrn",
  "insurancenumber",
  "taxid",
];

// WORDS MUST BE SANITIZED BEFORE USING THIS
export const SANITIZED_PII_WORDS_HIDE = [
  // personal info
  "firstname",
  "fullname",
  "preferredName",
  "contact",
  "legalName",
  "lastname",
  "email",
  "emailaddress",
  "phone",
  "phonenumber",
  "mobilenumber",
  // location related
  "coordinates",
  "location",
  "latitude",
  "longitude",
  "address",
  "zipcode",
  "country",
  "county",
  "streetaddress",
  "city",
  "postalcode",
  // hide should include remove just in case
  ...SANITIZED_PII_WORDS_REMOVE,
];

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

export const LAT_LONG_REJEX =
  /^((\-?|\+?)?\d+(\.\d+)?),\s*((\-?|\+?)?\d+(\.\d+)?)$/;
export const PASSWORD_REJEX =
  /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{8,}$/;
export const EMAIL_REJEX =
  /(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/;
export const SSN_REJEX =
  /^(?!0{3})(?!6{3})[0-8]\d{2}-(?!0{2})\d{2}-(?!0{4})\d{4}$/;
export const PHONE_NUMBER_REJEX =
  /^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$/;
export const IPV4_REJEX =
  /(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}/;
export const IPV6_REJEX =
  /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/;
export const CREDIT_CARD_REJEX = /\b\d{15,}\b/;

// WORDS MUST BE SANITIZED BEFORE USING THIS
export const SANITIZED_PII_WORDS = [
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
  "name",
  "firstname",
  "lastname",
  "email",
  "emailaddress",
  "phone",
  "phonenumber",
  "mobilenumber",
  "ssn",
  "socialsecuritynumber",
  "creditcardnumber",
  "ccnumber",
  "cardnumber",
  "bankaccountnumber",
  "driverslicense",
  "passportnumber",
  "medicalrecordnumber",
  "mrn",
  "insurancenumber",
  "taxid",
  "tin",
  // location related
  "coordinates",
  "location",
  "lat",
  "long",
  "latitude",
  "longitude",
  "address",
  "streetaddress",
  "city",
  "state",
  "zip",
  "postalcode",
];

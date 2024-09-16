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

export type Logger = Record<
  "off" | "fatal" | "error" | "warn" | "info" | "debug" | "trace" | "all",
  Function
>;

export type LoggerFunction = (level: LogLevel, ...args: any[]) => void;

export enum LogLevel {
  "off" = 0,
  "fatal" = 100,
  "error" = 200,
  "warn" = 300,
  "info" = 400,
  "debug" = 500,
  "trace" = 600,
  "all" = Number.MAX_VALUE,
}

export enum MaskLevel {
  REMOVE = "REMOVE", // Masks very obviously critical data -- data that is removed will not be searchable and will not ever be displayed or stored anywhere
  HIDE = "HIDE", // Masks almost obviously critical data -- data this is hidden will be searchable but will not be displayed unless requested. Which we will also track lol.
}

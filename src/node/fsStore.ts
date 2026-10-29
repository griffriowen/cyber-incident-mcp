import fs from "node:fs";
import path from "node:path";
import { initStore, type StoreData } from "../store/ticketStore.js";

/** Node host: loads mock data from data/mock and writes tickets and calls back to disk. */
export function initFsStore(): void {
  const dataDir = path.resolve(process.cwd(), "data/mock");
  const ticketPath = path.resolve(process.cwd(), process.env.TICKET_STORE_PATH ?? "data/mock/tickets.json");
  const callPath = path.resolve(process.cwd(), process.env.CALL_STORE_PATH ?? "data/mock/calls.json");
  const read = <T>(file: string, fallback: T): T => {
    try {
      return JSON.parse(fs.readFileSync(file, "utf8")) as T;
    } catch {
      return fallback;
    }
  };
  const data: StoreData = {
    tickets: read(ticketPath, []),
    calls: read(callPath, []),
    customers: read(path.join(dataDir, "mock_customers.json"), []),
    knownIncidents: read(path.join(dataDir, "known_incidents.json"), []),
  };
  initStore(data, (d) => {
    fs.writeFileSync(ticketPath, JSON.stringify(d.tickets, null, 2));
    fs.writeFileSync(callPath, JSON.stringify(d.calls, null, 2));
  });
}

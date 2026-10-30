import fs from "node:fs";
import path from "node:path";
import { incidentsToSave, initStore, mergeIncidents, type StoreData } from "../store/ticketStore.js";

/** Node host: loads mock data from data/mock and writes tickets and calls back to disk. */
export function initFsStore(): void {
  const dataDir = path.resolve(process.cwd(), "data/mock");
  const ticketPath = path.resolve(process.cwd(), process.env.TICKET_STORE_PATH ?? "data/mock/tickets.json");
  const callPath = path.resolve(process.cwd(), process.env.CALL_STORE_PATH ?? "data/mock/calls.json");
  // Auto-detected incidents live apart from the seed file so redeploys don't wipe them.
  const incidentPath = path.resolve(process.cwd(), process.env.INCIDENT_STORE_PATH ?? "data/mock/auto_incidents.json");
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
    knownIncidents: mergeIncidents(
      read<StoreData["knownIncidents"]>(path.join(dataDir, "known_incidents.json"), []),
      read<StoreData["knownIncidents"]>(incidentPath, []),
    ),
  };
  initStore(data, (d) => {
    fs.writeFileSync(ticketPath, JSON.stringify(d.tickets, null, 2));
    fs.writeFileSync(callPath, JSON.stringify(d.calls, null, 2));
    // Seed incidents can be resolved on the desk too, so store every incident that has changed or was auto-detected.
    fs.writeFileSync(incidentPath, JSON.stringify(incidentsToSave(d.knownIncidents), null, 2));
  });
}

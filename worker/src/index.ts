/** Worker entrypoint: every request goes to the single relay Durable Object. */
import { Env, RelayDO } from "./relay";

export { RelayDO };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const stub = env.RELAY.get(env.RELAY.idFromName("relay"));
    return stub.fetch(request);
  },
} satisfies ExportedHandler<Env>;

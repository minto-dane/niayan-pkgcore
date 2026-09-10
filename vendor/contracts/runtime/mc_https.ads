-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Store;
package MC_HTTPS with SPARK_Mode => Off is
   procedure Fetch(URL, Allowed_Origin : String; Expected : Digest; Expected_Size : Counter;
      Deadline : Counter; Store : in out MC_Store.Store; Status : out Outcome);
   -- Store only: no host installation. Caller authenticates URL/hash/size/freshness
   -- before calling. Only HTTPS, exact approved origin, no redirects/proxies/netrc,
   -- mandatory peer+hostname verification, TLS>=1.2 and exact content hashing.
   -- libcurl >=7.85, libcurl/TLS/DNS trust store in TCB. Single-threaded synchronous
   -- caller; run ingestion as an unprivileged, network-restricted worker.
end MC_HTTPS;

-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types; with MC_Store; with Pkg_Payload_Map;
package Pkg_Archive with SPARK_Mode => Off is
   procedure Stage(S : in out MC_Store.Store; RPM : Digest; Map : Pkg_Payload_Map.Inventory;
                   Deadline : Counter; Status : out Outcome);
   -- libarchive read-only decoder into CAS, never archive_write_disk/extract.
   -- Explicit built-in filters only (no external program fallback). Hardlinks,
   -- devices and sparse archives are unsupported rather than silently normalized.
   -- Run in the unprivileged, resource-limited stage worker; this is outside SPARK.
end Pkg_Archive;

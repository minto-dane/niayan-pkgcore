-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with MC_Store; with MC_Signatures;
package Pkg_Archive_Supply with SPARK_Mode => Off is
   Body_Size : constant := 256;
   Wire_Size : constant := 320;
   Max_Lifetime : constant Counter := 3_600;
   type Authority is record
      Scope : Digest := Zero_Digest;
      Key : MC_Signatures.Public_Key := (others => 0);
      Minimum_Epoch, Maximum_Age : Counter := 0;
   end record;
   procedure Verify_Original (Store : in out MC_Store.Store;
      Receipt, Original, Control : Digest; Trusted : Authority;
      Now, Deadline : Counter; Binding : out Digest; Status : out Outcome);
   -- NIASUP01: tag[8], scope/policy/original/raw-control/InRelease/Packages/
   -- keyring digests[7*32], security epoch/checked-at/expires[u64 BE each],
   -- Ed25519 signature[64]. MC_Authentic domain is NiaOS/archive-supply/v1.
   -- Trusted scope/key/epoch floor/maximum age and current UTC seconds come
   -- from independent protected site policy, NEVER fields supplied by a receipt.
   -- Now is sampled at entry; elapsed BOOTTIME is conservatively added before
   -- returning. Both the receipt and the call have finite exclusive deadlines.
   -- Every referenced CAS object must already exist and rehash correctly before
   -- native DEB metadata inspection; missing control is not regenerated to pass.
   -- Inspection reobserves the original's raw control and may retain other
   -- derived objects. Binding is the verified receipt CAS address only on full
   -- success; every failure clears it. UID 0 is refused. The open Store retains
   -- the caller's reservation. No pin, installed state or execution grant is
   -- created. Upstream metadata is authenticated by the scoped issuing observer;
   -- this reader verifies that observer and the actual native originals.
   -- Production observer/key provisioning, rollback-resistant floors/time,
   -- whole-plan coverage and retained generation linkage remain caller duties.
end Pkg_Archive_Supply;

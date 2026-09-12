-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Finalization; with System;
with MC_Types; use MC_Types;
package Pkg_Operator_Authorization with SPARK_Mode => Off is
   type Session is new Ada.Finalization.Limited_Controlled with private;
   procedure Open (C : in out Session; Peer_FD : Integer; Plan : Digest;
      Request_ID : Identity; Deadline : Counter; Interactive : Boolean; Status : out Outcome);
   procedure Check (C : in out Session; Plan : Digest; Request_ID : Identity; Status : out Outcome);
   procedure Close (C : in out Session);
   overriding procedure Finalize (C : in out Session);
   -- Root-supervisor-only polkit decision for the actual accepted seqpacket
   -- peer. Consume and authenticate its request before Open; a new packet,
   -- disconnect or peer death invalidates this decision. Peer_FD is borrowed.
   -- SO_PEERPIDFD and SO_PEERCRED supply subject identity; no PID fallback or
   -- claimed UID is accepted. The fixed system bus and well-known authority are
   -- used independently of environment variables. Exact plan/request details
   -- accompany the check. The supervisor must derive these from its admitted
   -- immutable operation, never treat this decision as proof of those inputs.
   -- At most 120 seconds of BOOTTIME, no renewal or retained polkit ticket.
   -- Check verifies the exact same context, peer lifetime, current authority
   -- owner, and ordered Changed notifications. Failure poisons the session.
   -- This is operator authorization, not exact-plan consent, a signed supply
   -- decision, generation admission, physical exclusion or revocation of effects
   -- already started. Those guards remain mandatory at the actual writer.
   -- No grant file, native ledger, password storage, process privilege change,
   -- public CLI, or package effect is created. Single owning process/task only.
private
   type Session is new Ada.Finalization.Limited_Controlled with record
      Handle : System.Address := System.Null_Address;
   end record;
end Pkg_Operator_Authorization;

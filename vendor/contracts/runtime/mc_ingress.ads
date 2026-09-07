-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with MC_Signatures; with MC_Authorization; with MC_Replay; with MC_Requests;
package MC_Ingress with SPARK_Mode => Off is
   procedure Check_Request
     (Raw_Header, Body_Data : Bytes; Sig : MC_Signatures.Signature;
      Key : MC_Signatures.Public_Key; Scope : MC_Authorization.Scope;
      Expected_Contract : Digest; Now : Counter; Previous : MC_Replay.Window;
      Candidate : out MC_Replay.Window; Request : out MC_Requests.Request;
      Classification : out MC_Replay.Decision; Status : out Outcome);
   -- This is a checked ingress pipeline, not a transport or an executor.
   -- Candidate must be atomically persisted with request/outcome state BEFORE effects.
   -- Exact_Retry requires outcome inspection; it must never re-execute an unknown effect.
   -- The scoped key, Scope and Expected_Contract must come from independently authenticated local policy.
end MC_Ingress;

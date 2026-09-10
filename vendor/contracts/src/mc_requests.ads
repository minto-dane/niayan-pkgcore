-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Protocol;
package MC_Requests with SPARK_Mode, Pure is
   Body_Size : constant := 192;
   subtype Request_Bytes is Bytes(1..Body_Size);
   type Requested_Action is (Plan, Prepare, Apply, Inspect, Recover, Commit, Restore, Reconcile, Repair);
   type Request is record
      Action : Requested_Action := Inspect;
      Transaction_ID : Identity := Zero_Identity;
      Plan_Digest : Digest := Zero_Digest;
      Contract_Digest : Digest := Zero_Digest;
      Expected_Revision : Counter := 0;
      Base_Generation : Counter := 0;
      Stage_Set_Digest : Digest := Zero_Digest;
      Evidence_Digest : Digest := Zero_Digest;
   end record;
   function Encode (R : Request) return Request_Bytes with Global => null;
   procedure Decode (Data : Bytes; R : out Request; Status : out Outcome) with Global => null;
   function Header_Binds (H : MC_Protocol.Header; R : Request) return Boolean with Global => null;
   -- Requests contain content references, never shell commands, arbitrary paths,
   -- "verified=true" booleans or authorization claims supplied by the requester.
end MC_Requests;

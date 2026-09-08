-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package MC_Control with SPARK_Mode, Pure is
   Max_Signers : constant := 8;
   subtype Signer_Index is Positive range 1 .. Max_Signers;
   type Role is (Operations, Security);
   type Signer is record
      Public_Key : Digest := Zero_Digest;
      Principal : Identity := Zero_Identity;
      Domain : Natural range 0 .. 65_535 := 0;
      Duty : Role := Operations;
   end record;
   type Signers is array (Signer_Index) of Signer;
   type Verified_Set is array (Signer_Index) of Boolean;
   type Authority is record
      Scope : Identity := Zero_Identity;
      Contract : Digest := Zero_Digest;
      Serial : Counter := 0;
      Count : Natural range 0 .. Max_Signers := 0;
      Tighten_Threshold : Positive range 1 .. Max_Signers := 1;
      Resume_Threshold : Positive range 2 .. Max_Signers := 2;
      Keys : Signers;
   end record;
   type Mode is (Running, Changes_Held, Quarantined);
   type Operation is
     (Inspect, Contain, Repair_Records, Change_Files, Activate_Service,
      Accept_State, Join_Cluster, Fleet_Step, Restore_State);
   type State is record
      Scope : Identity := Zero_Identity;
      Contract, Authority_Digest : Digest := Zero_Digest;
      Revision, Trust_Epoch : Counter := 0;
      Current : Mode := Quarantined;
      Incident, Last_Request : Identity := Zero_Identity;
      Previous, Reason : Digest := Zero_Digest;
   end record;
   type Proposal is record
      Scope, Boot_ID, Request_ID : Identity := Zero_Identity;
      Contract, Authority_Digest, Expected_State : Digest := Zero_Digest;
      Reason, Recovery_Receipt : Digest := Zero_Digest;
      Expected_Revision, New_Trust_Epoch, Not_Before, Expires : Counter := 0;
      Desired : Mode := Quarantined;
   end record;
   function Valid (A : Authority) return Boolean with Global => null,
     Post => (if Valid'Result then A.Scope/=Zero_Identity and then A.Contract/=Zero_Digest
       and then A.Serial>0 and then A.Count>=2
       and then A.Tighten_Threshold<=A.Count and then A.Resume_Threshold<=A.Count);
   function Valid (S : State) return Boolean with Global => null;
   function Permits (Current : Mode; Action : Operation) return Boolean
      with Global => null;
   procedure Decide
     (A : Authority; Authority_Hash : Digest; Before : State;
      Before_Hash : Digest; Is_Genesis : Boolean; P : Proposal;
      Verified : Verified_Set; Boot : Identity; Now : Counter;
      After : out State; Status : out Outcome)
      with Global => null,
        Post => (if Status /= OK then After = Before)
          and then (if Status = OK then Valid (After)
             and then After.Revision = P.Expected_Revision + 1
             and then After.Trust_Epoch = P.New_Trust_Epoch);
   -- Verified is produced ONLY by verifying the same canonical proposal against
   -- provisioned keys. A Boolean received over a connector is not a signature.
   -- Relaxing a latch requires independent operations/security principals in
   -- distinct domains, an increasing trust epoch and a bound recovery receipt.
   -- Modes never expire automatically. This is a dispatch interlock, not a way
   -- to cancel an already-dispatched external operation.
end MC_Control;

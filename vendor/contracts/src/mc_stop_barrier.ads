-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types; with MC_Time_Guard;
package MC_Stop_Barrier with SPARK_Mode, Pure is
   Capacity : constant := 32;
   subtype Index is Positive range 1..Capacity;
   type Participant is record
      Node_ID, Resource_ID, Boot_ID : Identity := Zero_Identity;
      Stop_Key, Fence_Key : Digest := Zero_Digest;
      Required_Isolation_Paths : Word := 0;
   end record;
   type Participants is array (Index) of Participant;
   type Policy is record
      Cluster_ID, Barrier_ID, Receiver_Boot : Identity := Zero_Identity;
      Contract, Change_Plan, Inventory, Guard_Value : Digest := Zero_Digest;
      Epoch, Guard_Revision : Counter := 0;
      Maximum_Age : Counter := 5_000;
      Count : Natural range 0..Capacity := 0;
      Members : Participants;
   end record;
   type Ack_Kind is (Drained, Fenced, Unsafe);
   type Channel is (Node_Agent, Fence_Observer);
   type Evidence is record
      Policy_Hash, Durable_Receipt, Audit_Head : Digest := Zero_Digest;
      Node_ID, Resource_ID, Subject_Boot : Identity := Zero_Identity;
      Stamp : MC_Time_Guard.Stamp;
      Epoch, Applied_Guard_Revision, Last_Dispatched, Last_Completed : Counter := 0;
      In_Flight, Unknown_Effects : Counter := 0;
      Isolation_Paths : Word := 0;
      Kind : Ack_Kind := Unsafe;
      Source : Channel := Node_Agent;
      Durable_Stop_Latch, Queue_Closed, Retirement_Durable : Boolean := False;
   end record;
   type Phase is (Collecting, Sealed, Blocked);
   type Participant_Phase is (Awaiting, Acknowledged, Isolated, Uncertain);
   type Receipt is record
      Current : Participant_Phase := Awaiting;
      Node_Sequence, Fence_Sequence, Observed, Expires : Counter := 0;
      Proof, Audit_Head : Digest := Zero_Digest;
      Completed : Counter := 0;
      Isolation_Paths : Word := 0;
   end record;
   type Receipts is array (Index) of Receipt;
   type State is record
      Policy_Hash : Digest := Zero_Digest;
      Cluster_ID, Barrier_ID, Receiver_Boot : Identity := Zero_Identity;
      Revision, Last_Now : Counter := 0;
      Current : Phase := Collecting;
      Count : Natural range 0..Capacity := 0;
      Members : Receipts;
   end record;
   subtype Policy_Frame is Bytes (1..4_608);
   subtype State_Frame is Bytes (1..4_608);
   subtype Evidence_Frame is Bytes (1..320);
   function Valid (P : Policy) return Boolean with Global => null;
   function Valid (S : State) return Boolean with Global => null;
   function Fingerprint (P : Policy) return Digest with Global => null;
   function Ready (P : Policy; S : State; Now : Counter) return Boolean with Global => null;
   function Usable (P : Policy; S : State; Now : Counter) return Boolean with Global => null;
   procedure Initialize (P : Policy; S : out State; Status : out Outcome) with Global => null;
   procedure Observe (P : Policy; S : in out State; E : Evidence;
      Signature_Verified : Boolean; Now : Counter; Status : out Outcome)
      with Global => null, Post => (if Status /= OK then S = S'Old)
        and then (if Status = OK then Valid (S) and then S.Revision = S'Old.Revision + 1);
   procedure Seal (P : Policy; S : in out State; Now : Counter; Status : out Outcome)
      with Global => null, Post => (if Status /= OK then S = S'Old)
        and then (if Status = OK then S.Current = Sealed and then Usable (P,S,Now));
   function Encode (P : Policy) return Policy_Frame with Global => null;
   function Encode (S : State) return State_Frame with Global => null;
   function Encode (E : Evidence) return Evidence_Frame with Global => null;
   procedure Decode (B : Bytes; P : out Policy; Status : out Outcome) with Global => null;
   procedure Decode (B : Bytes; S : out State; Status : out Outcome) with Global => null;
   procedure Decode (B : Bytes; E : out Evidence; Status : out Outcome) with Global => null;
   -- Every participant in the authenticated inventory must acknowledge OR be
   -- durably isolated. This is NOT quorum: a minority may still run old effects.
   -- No expiry, heartbeat failure, majority vote or restart removes a participant.
   -- Receipt clocks are receiver-local and bound to Receiver_Boot. A controller
   -- reboot requires a newly authorized barrier and new observations.
   -- Usable must be checked when using a sealed result, not just at sealing time.
   -- Missing observers/transport do not become success-valued stubs.
end MC_Stop_Barrier;

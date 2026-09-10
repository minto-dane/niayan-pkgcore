-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Signatures; with MC_Protocol; with MC_Requests; with MC_Site_Policy;
with MC_Witness; with MC_FS; with MC_Log;
package MC_Gate with SPARK_Mode => Off is
   type Admission is (New_Request, Known_Retry, Unknown_Retry);
   type Witness_Frame_Array is array(MC_Witness.Fact) of MC_Witness.Frame;
   type Witness_Sig_Array is array(MC_Witness.Fact) of MC_Signatures.Signature;
   type Presence is array(MC_Witness.Fact) of Boolean;
   type Witness_Set is record
      Present : Presence := (others=>False);
      Statements : Witness_Frame_Array := (others=>(others=>0));
      Signatures : Witness_Sig_Array := (others=>(others=>0));
   end record;
   type Session is limited private;
   procedure Begin_Request(Policy_Directory, Ledger_Directory : String;
      Header, Body_Data : Bytes; Signature : MC_Signatures.Signature;
      Witnesses : Witness_Set; S : in out Session; Mode : out Admission; Status : out Outcome);
   procedure Check(S : in out Session; Root_ID, Transaction_ID : Identity;
      Plan, Evidence : Digest; Origin_Epoch, Origin_Fence : Counter;
      Phase : String; Status : out Outcome);
   procedure Finish(S : in out Session; Result : Outcome; Status : out Outcome);
   procedure Repair_Ledger(Policy_Directory, Ledger_Directory, Store_Directory : String;
      Header, Body_Data : Bytes; Signature : MC_Signatures.Signature;
      Witnesses : Witness_Set; Status : out Outcome);
   -- Offline, independently signed REPAIR request plus reservation/isolation
   -- witnesses. Repairs partial tail only, preserving bytes and before-head first.
   -- Always leaves the effect outcome UNKNOWN for explicit follow-up reconciliation.
   procedure Refresh_Witnesses(S : in out Session; W : Witness_Set);
   function Health_Observer_Allowed(S : Session; Key : MC_Signatures.Public_Key) return Boolean;
   function Deadline(S : Session) return Counter;
   function Receipt_Result(S : Session) return Outcome;
   function Request(S : Session) return MC_Requests.Request;
   procedure Close(S : in out Session);
   -- Durable receipt before effects; exact retransmission never re-executes.
   -- Admission requires independently provisioned policy and signed witnesses.
   -- Quorum/fencing truth is the observer's responsibility, not implied by a signature.
private
   type Session is limited record
      Policy_Root, Ledger_Root : MC_FS.Root;
      Journal : MC_Log.Journal;
      Policy : MC_Site_Policy.Policy;
      Policy_Digest : Digest := Zero_Digest;
      Header : MC_Protocol.Header;
      Content : MC_Requests.Request;
      Witnesses : Witness_Set;
      Admitted, Pending : Boolean := False;
      Last_Result : Outcome:=Indeterminate;
   end record;
end MC_Gate;

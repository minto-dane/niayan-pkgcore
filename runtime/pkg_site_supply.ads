-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Text; with Pkg_Supply_Map; with Pkg_Supply_Policy;
package Pkg_Site_Supply with SPARK_Mode => Off is
   Header_Size : constant := 56;
   Entry_Size : constant := 80;
   Maximum_Size : constant := Header_Size + Entry_Size * Pkg_Supply_Map.Max_Authorities;
   Floor_Size : constant := 72;
   type Policy is record
      Root_ID : Identity := Zero_Identity;
      Serial, Not_Before, Expires : Counter := 0;
      Count : Natural range 0 .. Pkg_Supply_Map.Max_Authorities := 0;
      Trusted : Pkg_Supply_Map.Authorities (1 .. Pkg_Supply_Map.Max_Authorities);
   end record;
   type Floor is record
      Root_ID : Identity := Zero_Identity;
      Minimum_Serial, Minimum_UTC : Counter := 0;
      Policy_Hash : Digest := Zero_Digest;
   end record;
   procedure Decode (Wire : Bytes; Value : out Policy; Status : out Outcome);
   procedure Decode_Floor (Wire : Bytes; Value : out Floor; Status : out Outcome);
   -- Parsing alone grants no authority. Only Open/Observe authenticate the
   -- independent protected filesystem inputs and sample the actual OS clock.
   type Session is limited private;
   procedure Open (Policy_Directory, Floor_Directory : String;
      Root_ID, Transaction_ID : Identity; Plan, Retained_Policy, Map : Digest;
      Deadline : Counter; Context : in out Session; Status : out Outcome);
   procedure Observe (Context : in out Session; Root_ID, Transaction_ID : Identity;
      Plan, Retained_Policy : Digest; Value : out Pkg_Supply_Policy.Snapshot; Status : out Outcome);
   procedure Close (Context : in out Session);
   generic
      Context : in out Session;
   procedure Observe_Current (Root_ID, Transaction_ID : Identity; Plan, Retained_Policy : Digest;
      Value : out Pkg_Supply_Policy.Snapshot; Status : out Outcome);
   -- Signature-compatible with the publisher's mandatory Observe_Supply gate.
   -- Each call rereads root-owned supply.bin and supply.floor through protected
   -- root-owned ancestor directories. The floor pins the complete policy hash;
   -- neither keys nor time come from the CAS/receipt/retained policy. No CAS
   -- open/reacquisition, filesystem write, key generation or fallback occurs.
   -- The bound map/transaction/plan are caller context, NOT independently granted
   -- execution authority. The publisher still proves the exact retained map,
   -- receipts, predecessor and all managed guards under its own reservations.
   -- Any observation failure poisons the session and clears the observation. Policy/floor
   -- changes require a new explicit Open, never mid-operation adoption.
   -- Deadline is finite BOOTTIME; UTC is independently sampled and cannot fall
   -- below the external floor or the session's high water mark. Protecting that
   -- floor from whole-volume rollback and establishing correct time remain site
   -- duties; root ownership is not a hardware-backed rollback guarantee.
private
   type State is record
      Active : Boolean := False;
      Policy_Path, Floor_Path : MC_Text.Value := MC_Text.Empty;
      Root_ID, Transaction_ID : Identity := Zero_Identity;
      Plan, Retained_Policy, Map : Digest := Zero_Digest;
      Policy_Hash, Floor_Hash : Digest := Zero_Digest;
      Deadline, Last_UTC : Counter := 0;
   end record;
   type Session is limited record
      Data : State;
   end record;
end Pkg_Site_Supply;

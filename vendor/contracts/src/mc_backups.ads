-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package MC_Backups with SPARK_Mode, Pure is
   Capacity : constant := 64;
   Max_Copies : constant := 8;
   subtype Index is Positive range 1 .. Capacity;
   subtype Copy_Index is Positive range 1 .. Max_Copies;
   type Copy_Receipt is record
      Store_ID : Identity := Zero_Identity;
      Domain_ID : Natural range 0 .. 65_535 := 0;
      Object_Hash, Receipt_Hash : Digest := Zero_Digest;
      Valid_Until, Immutable_Until : Counter := 0;
      Authenticated, Integrity_Verified, Durable : Boolean := False;
   end record;
   type Copies is array (Copy_Index) of Copy_Receipt;
   type Backup is record
      Scope, Dataset, Lineage : Identity := Zero_Identity;
      Manifest, Payload, Parent, Restore_Test_Chain : Digest := Zero_Digest;
      From_Position, Through_Position, Completed_At, Tested_At, Trust_Epoch : Counter := 0;
      Retain_Until : Counter := 0;
      Full, Authenticated, Header_Payload_Bound, Key_Available : Boolean := False;
      Key_Revoked, Integrity_Incident : Boolean := True;
      Pinned, In_Use, Legal_Hold : Boolean := True;
      Locations : Copies;
   end record;
   type Catalog is array (Index) of Backup;
   type Selection is array (Index) of Boolean;
   type Policy is record
      Scope, Dataset, Lineage : Identity := Zero_Identity;
      Now_Lower, Now_Upper, Required_Position, Minimum_Trust_Epoch : Counter := 0;
      Maximum_Test_Age, Immutable_For : Counter := 0;
      Minimum_Copies, Minimum_Domains : Positive range 1 .. Max_Copies := 2;
   end record;
   function Valid (P : Policy) return Boolean with Global => null;
   function Valid_Catalog (C : Catalog; Count : Natural) return Boolean
     with Global => null, Post => (if Valid_Catalog'Result then Count in 1 .. Capacity);
   procedure Chain (C : Catalog; Count, Terminal : Natural; Members : out Selection;
      Commitment : out Digest; Status : out Outcome) with Global => null,
        Post => (if Status = OK then Count in 1 .. Capacity and then Terminal in 1 .. Count);
   function Usable (P : Policy; B : Backup) return Boolean with Global => null;
   procedure Restore_Set (P : Policy; C : Catalog; Count, Terminal : Natural;
      Members : out Selection; Status : out Outcome) with Global => null;
   procedure Choose (P : Policy; C : Catalog; Count : Natural;
      Terminal : out Natural; Members : out Selection; Status : out Outcome) with Global => null;
   -- All typed metadata and receipts must be authenticated by a connector before
   -- setting Authenticated. Signatures do not prove storage independence or truth.
   -- Positions are compared ONLY within the same dataset+lineage+adapter semantics.
   -- Full/incremental parent closure and exact restore-test chain binding required.
end MC_Backups;

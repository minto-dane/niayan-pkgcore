-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with MC_Store; with Pkg_File_Plan;
package Pkg_Generation_Manifest with SPARK_Mode => Off is
   Max_Batches : constant := 512;
   Max_Entries : constant := Max_Batches * Pkg_File_Plan.Max_Changes;
   Header_Size : constant := 160;
   Max_Bytes : constant := Header_Size + 64 * Max_Batches;
   type Batch is record
      Plan, Receipt : Digest := Zero_Digest;
   end record;
   type Batch_Array is array (Positive range 1 .. Max_Batches) of Batch;
   type Manifest is record
      Stage_ID, Transaction_ID : Identity := Zero_Identity;
      Epoch, Fence : Counter := 0;
      Catalog, Effect_Contract : Digest := Zero_Digest;
      Entries : Natural range 0 .. Max_Entries := 0;
      Count : Natural range 0 .. Max_Batches := 0;
      Batches : Batch_Array;
   end record;
   function Valid (M : Manifest) return Boolean;
   procedure Encode (M : Manifest; B : out Bytes; Used : out Natural; Status : out Outcome);
   procedure Decode (B : Bytes; M : out Manifest; Status : out Outcome);
   function Transaction (M : Manifest; Index : Positive) return Identity;
   procedure Load_Plan (S : MC_Store.Store; M : Manifest; Index : Positive;
                        P : out Pkg_File_Plan.Plan; Status : out Outcome);
   procedure Check (S : MC_Store.Store; M : Manifest; Status : out Outcome);
   -- Content-bound staging format, never an authorization or installed database.
   -- Each batch creates absent objects only, in component-wise preorder. The
   -- first two entries are catalog (regular, hash=M.Catalog) and tree (directory).
   -- Every other entry is under tree/, with all parents explicitly declared.
   -- Logical paths retain file-plan exclusions even below the tree/ wrapper.
   -- Receipts must be independently authenticated by the stage authorizer.
end Pkg_Generation_Manifest;

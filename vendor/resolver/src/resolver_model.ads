-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package Resolver_Model with SPARK_Mode, Pure is
   -- All identifiers refer to the authenticated, closed universe, not to a
   -- solver's mutable numbering. The core contains NO native version ordering.
   Max_Items : constant := 4_096;
   Max_Nodes : constant := 16_384;
   Max_Rules : constant := 16_384;
   Max_Claims : constant := 16_384;
   Max_Steps : constant := 8_192;
   subtype Item_ID is Natural range 0 .. Max_Items;
   subtype Node_ID is Natural range 0 .. Max_Nodes;
   type Selection is array (Positive range 1 .. Max_Items) of Boolean;
   type Truth_Array is array (Positive range 1 .. Max_Nodes) of Boolean;
   type Pin_Mode is (Unpinned, Keep_State, Require_Present, Require_Absent);
   type Item is record
      Object_Hash, Metadata_Hash, Adapter_Hash : Digest := Zero_Digest;
      Initially_Present, Permitted, Reinstall_Requested : Boolean := False;
      Pin : Pin_Mode := Unpinned;
      Transfer_Bytes : Counter := 0;
      Add_Pre, Add_Post, Remove_Pre, Remove_Post : Node_ID := 0;
      -- Zero predicate = True; nonzero predicates are manifest-owned, not
      -- supplied by the proposed action sequence.
   end record;
   type Item_Array is array (Positive range 1 .. Max_Items) of Item;
   type Operator is (Constant_False, Constant_True, Present, Not_Op, And_Op, Or_Op);
   type Expression_Node is record
      Op : Operator := Constant_False;
      Subject : Item_ID := 0;
      Left, Right : Node_ID := 0;
   end record;
   type Node_Array is array (Positive range 1 .. Max_Nodes) of Expression_Node;
   type Rule_Scope is (Final_State, Every_Boundary);
   type Rule is record
      Predicate : Node_ID := 0;
      Scope : Rule_Scope := Final_State;
      Origin : Digest := Zero_Digest;
   end record;
   type Rule_Array is array (Positive range 1 .. Max_Rules) of Rule;
   type Claim is record
      Resource, Content, Attributes : Digest := Zero_Digest;
      Owner : Item_ID := 0;
      Shared_Identical : Boolean := False;
   end record;
   type Claim_Array is array (Positive range 1 .. Max_Claims) of Claim;
   type Binding is record
      Root, Boot, Snapshot, Policy, Adapter_Set, Native_Inventory,
        Configuration, Effect_Contracts : Digest := Zero_Digest;
      Generation : Counter := 0;
   end record;
   type Universe is record
      Subject : Binding;
      Item_Count : Item_ID := 0;
      Node_Count : Node_ID := 0;
      Rule_Count : Natural range 0 .. Max_Rules := 0;
      Claim_Count : Natural range 0 .. Max_Claims := 0;
      Maximum_Changes : Natural range 0 .. Max_Steps := 0;
      Maximum_Transfer : Counter := 0;
      Items : Item_Array;
      Nodes : Node_Array;
      Rules : Rule_Array;
      Claims : Claim_Array;
   end record;
   type Action_Kind is (Add_Item, Remove_Item, Reinstall_Item);
   type Action is record
      Kind : Action_Kind := Add_Item;
      Subject : Item_ID := 0;
   end record;
   type Action_Array is array (Positive range 1 .. Max_Steps) of Action;
   type Proposal is record
      Universe_Hash : Digest := Zero_Digest;
      Selected : Selection := (others => False);
      Count : Natural range 0 .. Max_Steps := 0;
      Steps : Action_Array;
   end record;
   type Check_Code is (Valid_Selection, Valid_Schedule, Malformed_Universe,
      Invalid_Binding, Stale_Universe, Noncanonical_Tail, Bad_Selection,
      Policy_Violation, Constraint_Violation, Ownership_Conflict,
      Budget_Exceeded, Invalid_Action, Precondition_Failed,
      Postcondition_Failed, Final_Mismatch, Limit_Reached);
   type Report is record
      Code : Check_Code := Malformed_Universe;
      Item_Index, Rule_Index, Claim_Index, Step_Index : Natural := 0;
      Transfer_Bytes : Counter := 0;
      -- No check result is an execution capability.
      Execution_Permit : Boolean := False;
   end record;
   function Less (A, B : Digest) return Boolean with Global => null;
   function Binding_Valid (B : Binding) return Boolean with Global => null;
   function Well_Formed (U : Universe) return Boolean with Global => null;
   function Initial (U : Universe) return Selection with Global => null;
   function Canonical_Selection (U : Universe; S : Selection) return Boolean
     with Global => null;
   procedure Evaluate (U : Universe; S : Selection; Values : out Truth_Array)
     with Global => null, Pre => Well_Formed (U);
   function Predicate_Holds (ID : Node_ID; Values : Truth_Array) return Boolean
     with Global => null;
   function Claims_Compatible (A, B : Claim) return Boolean with Global => null;
end Resolver_Model;

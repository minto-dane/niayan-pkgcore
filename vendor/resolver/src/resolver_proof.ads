-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with Resolver_CNF;
package Resolver_Proof with SPARK_Mode is
   -- Independent, bounded RUP/RAT checker. It recomputes redundancy and does
   -- not use proof hints as authority. This source has NOT been proved.
   Max_Variables : constant := Resolver_CNF.Max_Variables;
   Max_Entries : constant := 262_144;
   Max_Literals : constant := 2_097_152;
   subtype Literal is Resolver_CNF.Literal;
   type Literals is array (Positive range <>) of Literal;
   type Database is limited private;
   procedure Initialize (F : Resolver_CNF.Formula; D : out Database;
      Status : out Outcome; Fuel : in out Natural) with Global => null;
   procedure Add (D : in out Database; ID : Counter; Clause : Literals;
      Status : out Outcome; Fuel : in out Natural) with Global => null;
   procedure Delete (D : in out Database; ID : Counter;
      Status : out Outcome; Fuel : in out Natural) with Global => null;
   function Refuted (D : Database) return Boolean with Global => null;
   function Last_ID (D : Database) return Counter with Global => null;
private
   type Clause_Entry is record
      ID : Counter := 0;
      Offset : Natural range 0 .. Max_Literals := 0;
      Length : Natural range 0 .. Max_Variables * 2 := 0;
      Active : Boolean := False;
   end record with Dynamic_Predicate =>
     Clause_Entry.Length<=Max_Literals-Clause_Entry.Offset;
   type Entries is array (Positive range 1 .. Max_Entries) of Clause_Entry;
   type Arena is array (Positive range 1 .. Max_Literals) of Literal;
   type Database is limited record
      Clauses : Entries;
      Data : Arena := (others => 0);
      Used : Natural range 0 .. Max_Entries := 0;
      End_Data : Natural range 0 .. Max_Literals := 0;
      Variables : Natural range 0 .. Max_Variables := 0;
      Maximum_ID : Counter := 0;
      Empty_Derived : Boolean := False;
      Initialized : Boolean := False;
   end record;
end Resolver_Proof;

-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with MC_Text; with Pkg_Deb_Fields; with Pkg_Deb_Semantics;
package Pkg_Deb_Relations with SPARK_Mode => Off is
   Max_Value : constant := 65_536;
   Max_Atoms : constant := 1_024;
   type Field_Kind is (Depends, Pre_Depends, Recommends, Suggests, Enhances,
      Breaks, Conflicts, Replaces, Provides, Built_Using, Static_Built_Using);
   type Expression is private;
   type Atom is record
      Name, Architecture, Version : MC_Text.Value;
      Operator : Pkg_Deb_Semantics.Relation := Pkg_Deb_Semantics.Any_Version;
      Group_Number : Natural := 0;
   end record;
   function Field_Name (Kind : Field_Kind) return String;
   procedure Parse (Value : String; Kind : Field_Kind;
                    Result : out Expression; Status : out Outcome);
   procedure Read_Field (Raw : Bytes; Fields : Pkg_Deb_Fields.Document;
                         Kind : Field_Kind; Result : out Expression; Status : out Outcome);
   procedure Validate_All (Raw : Bytes; Fields : Pkg_Deb_Fields.Document; Status : out Outcome);
   function Count (Value : Expression) return Natural;
   function Groups (Value : Expression) return Natural;
   function Kind_Of (Value : Expression) return Field_Kind;
   function Control_Hash (Value : Expression) return Digest;
   procedure Read_Atom (Value : Expression; Index : Positive; Result : out Atom; Status : out Outcome);
   -- Pure bounded binary-field grammar. Absence is an empty expression only
   -- through Read_Field, after checking the complete raw control hash.
   -- Alternatives retain order and group boundaries. Architecture labels are
   -- retained literally, not mapped to a native platform or wildcard policy.
   -- Neither syntax nor a matching atom grants dependency/effect permission.
private
   subtype Position is Natural range 0 .. Max_Value;
   type Span is record
      First, Last : Position := 0;
   end record;
   type Atom_Position is record
      Name, Architecture, Version : Span;
      Operator : Pkg_Deb_Semantics.Relation := Pkg_Deb_Semantics.Any_Version;
      Group_Number : Natural range 0 .. Max_Atoms := 0;
   end record;
   type Position_Array is array (Positive range 1 .. Max_Atoms) of Atom_Position;
   type Expression is record
      Text : String (1 .. Max_Value) := (others => Character'Val (0));
      Used : Position := 0;
      Kind : Field_Kind := Depends;
      Hash : Digest := Zero_Digest;
      Atom_Count, Group_Count : Natural range 0 .. Max_Atoms := 0;
      Atoms : Position_Array;
   end record;
end Pkg_Deb_Relations;

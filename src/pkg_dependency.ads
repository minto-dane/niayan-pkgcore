-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types; with MC_Text;
package Pkg_Dependency with SPARK_Mode, Pure is
   Max_Nodes : constant:=256; Max_Providers : constant:=2_048; Max_Packages : constant:=1_024;
   subtype Node_ID is Natural range 0..Max_Nodes;
   type Operator is (Capability, And_Op, Or_Op, With_Op, Without_Op, If_Op, Unless_Op);
   type Relation is (Any_Version, LT, LE, EQ, GE, GT);
   type Node is record
      Op : Operator:=Capability;
      Left, Right, Alternative : Node_ID:=0;
      Name, Version : MC_Text.Value;
      Comparison : Relation:=Any_Version;
   end record;
   type Node_Array is array(Positive range 1..Max_Nodes) of Node;
   type Expression is record Nodes : Node_Array; Count : Node_ID:=0; Root : Node_ID:=0; end record;
   type Provider is record
      Package_Index : Natural range 0..Max_Packages:=0;
      Name, Version : MC_Text.Value;
      Versioned : Boolean:=False;
   end record;
   type Provider_Array is array(Positive range 1..Max_Providers) of Provider;
   type Selection is array(Positive range 1..Max_Packages) of Boolean;
   procedure Parse(Text : String; E : out Expression; Status : out Outcome) with Global=>null;
   function Well_Formed(E : Expression) return Boolean is
     (E.Root in 1..E.Count and then (for all I in 1..E.Count =>
       (if E.Nodes(I).Op=Capability then
          MC_Text.Length(E.Nodes(I).Name)>0 and then E.Nodes(I).Left=0
          and then E.Nodes(I).Right=0 and then E.Nodes(I).Alternative=0
        else E.Nodes(I).Left in 1..I-1 and then E.Nodes(I).Right in 1..I-1
          and then E.Nodes(I).Alternative<I
          and then (E.Nodes(I).Alternative=0 or else E.Nodes(I).Op in If_Op | Unless_Op))))
     with Global=>null;
   procedure Evaluate(E : Expression; Providers : Provider_Array; Count : Natural;
      Selected : Selection; Satisfied : out Boolean; Status : out Outcome)
      with Global=>null, Pre=>Count<=Max_Providers;
   -- Exact evaluation for this supported bounded profile, not a SAT solver.
   -- with/without require a single matching selected package. Missing rich semantics
   -- or unsupported syntax fail closed; no string flattening into AND dependencies.
end Pkg_Dependency;

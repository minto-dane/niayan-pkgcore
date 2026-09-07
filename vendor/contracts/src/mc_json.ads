-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package MC_JSON with SPARK_Mode, Pure is
   Maximum_Nodes : constant:=4_096;
   subtype Index is Natural range 0..Maximum_Nodes;
   type Kind is (Object_Node, Array_Node, String_Node, Number_Node, True_Node, False_Node, Null_Node);
   type Node is record Node_Kind : Kind:=Null_Node; First,Last : Natural:=0; Parent,End_Index : Index:=0; end record;
   type Node_Array is array(Positive range 1..Maximum_Nodes) of Node;
   type Document is record Nodes : Node_Array; Count : Index:=0; end record;
   procedure Parse(Data : Bytes; D : out Document; Status : out Outcome) with Global=>null;
   function Member(Data : Bytes; D : Document; Object_Index : Index; Key : String) return Index with Global=>null;
   function Element(D : Document; Array_Index : Index; Position : Positive) return Index with Global=>null;
   procedure String_Bytes(Data : Bytes; D : Document; N : Index; Value : out Bytes; Used : out Natural; Status : out Outcome) with Global=>null;
   procedure Natural_Number(Data : Bytes; D : Document; N : Index; Value : out Counter; Status : out Outcome) with Global=>null;
   -- Strict bounded JSON output profile: no duplicate object keys, no Unicode
   -- escapes/non-ASCII, no floating point/exponents; depth<=24. Not a generic
   -- permissive JSON implementation. Unknown encodings fail closed.
end MC_JSON;

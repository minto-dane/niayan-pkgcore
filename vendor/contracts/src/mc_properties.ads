-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types; with MC_Text;
package MC_Properties with SPARK_Mode, Pure is
   Maximum : constant:=64;
   type Property is record Key, Value : MC_Text.Value; end record;
   type Property_Array is array(1..Maximum) of Property;
   type Document is record Items : Property_Array; Count : Natural range 0..Maximum:=0; end record;
   procedure Parse(Data : Bytes; D : out Document; Status : out Outcome) with Global=>null;
   procedure Get(D : Document; Key : String; V : out MC_Text.Value; Status : out Outcome) with Global=>null;
   function Has_Exactly(D : Document; Keys : String) return Boolean with Global=>null;
   -- Strict key=value, LF terminated, no spaces in keys, no quotes/escapes/comments,
   -- no duplicates or ignored records. Expected key set is comma separated.
end MC_Properties;

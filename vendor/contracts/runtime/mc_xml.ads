-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Text; with System;
package MC_XML with SPARK_Mode => Off is
   type Reader is limited private;
   type Node_Kind is (Element, End_Element, Text, Other_Node);
   procedure Open(Data : Bytes; R : in out Reader; Status : out Outcome);
   procedure Next(R : in out Reader; Available : out Boolean; Kind : out Node_Kind;
      Depth : out Natural; Name : out MC_Text.Value; Status : out Outcome);
   procedure Attribute(R : in out Reader; Name : String; V : out MC_Text.Value; Status : out Outcome);
   procedure Close(R : in out Reader);
   -- Bounded ASCII UTF-8 subset; rejects DTD/entity declarations, processing
   -- instructions, entity references, XInclude and namespaces. NONET; NOENT,
   -- DTDLOAD and HUGE are NEVER enabled. libxml2 remains in the TCB.
private
   type Buffer_Access is access Bytes;
   type Reader is limited record
      Handle : System.Address := System.Null_Address;
      Buffer : Buffer_Access := null;
      Steps : Natural:=0;
   end record;
end MC_XML;

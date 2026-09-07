-- SPDX-License-Identifier: MIT
with Ada.Text_IO;
package body Test_Support with SPARK_Mode => Off is
   Checks : Natural := 0;
   procedure Expect (Condition : Boolean; Name : String) is
   begin
      Checks := Checks+1;
      if not Condition then
         Ada.Text_IO.Put_Line(Ada.Text_IO.Standard_Error,"FAIL: " & Name);
         raise Failure with Name;
      end if;
   end Expect;
   procedure Report is
   begin Ada.Text_IO.Put_Line("PASS assertions=" & Natural'Image(Checks)); end Report;
   function Count return Natural is (Checks);
end Test_Support;

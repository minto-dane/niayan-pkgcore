-- SPDX-License-Identifier: MIT
package Test_Support with SPARK_Mode => Off is
   Failure : exception;
   procedure Expect (Condition : Boolean; Name : String);
   procedure Report;
   function Count return Natural;
end Test_Support;

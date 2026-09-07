-- SPDX-License-Identifier: MIT
with Interfaces.C; with System; with System.Address_To_Access_Conversions;
with MC_Text; with MC_Clock;
package body MC_HTTPS with SPARK_Mode => Off is
   use Interfaces.C; use type System.Address;
   function Init(Flags : long) return int with Import,Convention=>C,External_Name=>"curl_global_init";
   function New_Handle return System.Address with Import,Convention=>C,External_Name=>"curl_easy_init";
   procedure Cleanup(H : System.Address) with Import,Convention=>C,External_Name=>"curl_easy_cleanup";
   function Option_Long(H : System.Address; Option : int; Value : long) return int with Import,Convention=>C,External_Name=>"curl_easy_setopt";
   function Option_Ptr(H : System.Address; Option : int; Value : System.Address) return int with Import,Convention=>C,External_Name=>"curl_easy_setopt";
   function Option_Offset(H : System.Address; Option : int; Value : long_long) return int with Import,Convention=>C,External_Name=>"curl_easy_setopt";
   function Perform(H : System.Address) return int with Import,Convention=>C,External_Name=>"curl_easy_perform";
   function Get_Code(H : System.Address; Info : int; Value : access long) return int with Import,Convention=>C,External_Name=>"curl_easy_getinfo";
   type Writer_Access is access all MC_Store.Writer;
   type Transfer is record W : Writer_Access; Deadline : Counter; Status : Outcome:=OK; end record;
   package Access_Transfer is new System.Address_To_Access_Conversions(Transfer);
   function Receive(Data : System.Address; Size, Count : size_t; User : System.Address) return size_t
     with Convention=>C;
   function Receive(Data : System.Address; Size, Count : size_t; User : System.Address) return size_t is
      T : constant Access_Transfer.Object_Pointer:=Access_Transfer.To_Pointer(User);
      N : size_t; Now : Counter; S : Outcome;
   begin
      if T=null or else T.W=null or else T.Status/=OK or else Size=0 then return 0; end if;
      if Count>size_t'Last/Size then T.Status:=Exhausted; return 0; end if; N:=Size*Count;
      if N=0 then return 0; elsif N>1_048_576 or else Data=System.Null_Address then T.Status:=Exhausted; return 0; end if;
      MC_Clock.Boottime_Milliseconds(Now,S);
      if S/=OK or else Now>=T.Deadline then T.Status:=Stale; return 0; end if;
      declare B : Bytes(1..Natural(N)) with Import,Address=>Data; begin
         MC_Store.Write_Chunk(T.W.all,B,T.Status);
      end;
      if T.Status/=OK then return 0; end if; return N;
   exception when others=>if T/=null then T.Status:=IO_Error; end if; return 0;
   end;
   procedure Fetch(URL, Allowed_Origin : String; Expected : Digest; Expected_Size : Counter;
      Deadline : Counter; Store : in out MC_Store.Store; Status : out Outcome) is
      H : System.Address:=System.Null_Address; W : aliased MC_Store.Writer;
      T : aliased Transfer:=(W=>W'Unchecked_Access,Deadline=>Deadline,Status=>OK);
      U : aliased char_array:=To_C(URL); Proto : aliased char_array:=To_C("https");
      Empty : aliased char_array:=To_C(""); Code : aliased long:=0; RC : int; Now : Counter;
      Origin_End : Natural:=0;
      procedure L(Option : int; Value : long) is
      begin if Status=OK and then Option_Long(H,Option,Value)/=0 then Status:=Unsupported; end if; end;
      procedure P(Option : int; Value : System.Address) is
      begin if Status=OK and then Option_Ptr(H,Option,Value)/=0 then Status:=Unsupported; end if; end;
   begin
      Status:=Invalid_Input;
      if not MC_Text.HTTPS_URL(URL) or else Expected=Zero_Digest or else Expected_Size<=0
        or else Expected_Size>MC_Store.Max_Object_Size then return; end if;
      for I in URL'First+8..URL'Last loop if URL(I)='/' then Origin_End:=I-1; exit; end if; end loop;
      if Origin_End=0 or else URL(URL'First..Origin_End)/=Allowed_Origin then Status:=Denied; return; end if;
      MC_Clock.Boottime_Milliseconds(Now,Status); if Status/=OK then return; end if;
      if Deadline<=Now or else Deadline-Now>3_600_000 then Status:=Stale; return; end if;
      if Init(3)/=0 then Status:=IO_Error; return; end if;
      MC_Store.Begin_Write(Store,Expected,Expected_Size,W,Status); if Status/=OK then return; end if;
      H:=New_Handle; if H=System.Null_Address then MC_Store.Abort_Write(W); Status:=IO_Error; return; end if;
      P(10_002,U'Address); P(10_318,Proto'Address); P(10_319,Proto'Address); P(10_004,Empty'Address);
      P(20_011,Receive'Address); P(10_001,T'Address);
      L(64,1); L(81,2); L(32,6); L(45,1); L(51,0); L(52,0); L(99,1);
      L(155,long(Deadline-Now)); L(156,long(Counter'Min(15_000,Deadline-Now)));
      if Status=OK and then Option_Offset(H,30_117,long_long(Expected_Size))/=0 then Status:=Unsupported; end if;
      if Status=OK then
         RC:=Perform(H);
         if T.Status/=OK then Status:=T.Status;
         elsif RC/=0 then Status:=IO_Error;
         elsif Get_Code(H,16#20_0002#,Code'Access)/=0 or else Code/=200 then Status:=Denied; end if;
      end if;
      Cleanup(H); H:=System.Null_Address;
      if Status=OK then MC_Store.Finish_Write(Store,W,Status); end if;
      if Status/=OK then MC_Store.Abort_Write(W); end if;
   exception when others=>if H/=System.Null_Address then Cleanup(H); end if; MC_Store.Abort_Write(W); Status:=IO_Error;
   end Fetch;
end MC_HTTPS;

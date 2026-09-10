-- SPDX-License-Identifier: BSD-3-Clause
with Interfaces.C; with Interfaces.C.Strings; with Ada.Unchecked_Conversion; with Ada.Unchecked_Deallocation;
package body MC_XML with SPARK_Mode => Off is
   use type MC_Types.Byte;
   use Interfaces.C; use type System.Address; use type Interfaces.C.Strings.chars_ptr;
   function Create(B : System.Address; N : int; URL, Encoding : System.Address; Options : int) return System.Address
     with Import,Convention=>C,External_Name=>"xmlReaderForMemory";
   function Read_Node(R : System.Address) return int with Import,Convention=>C,External_Name=>"xmlTextReaderRead";
   function N_Type(R : System.Address) return int with Import,Convention=>C,External_Name=>"xmlTextReaderNodeType";
   function N_Depth(R : System.Address) return int with Import,Convention=>C,External_Name=>"xmlTextReaderDepth";
   function N_Name(R : System.Address) return System.Address with Import,Convention=>C,External_Name=>"xmlTextReaderConstLocalName";
   function N_NS(R : System.Address) return System.Address with Import,Convention=>C,External_Name=>"xmlTextReaderConstNamespaceUri";
   function N_Value(R : System.Address) return System.Address with Import,Convention=>C,External_Name=>"xmlTextReaderConstValue";
   function Move_Attr(R, Name : System.Address) return int with Import,Convention=>C,External_Name=>"xmlTextReaderMoveToAttribute";
   function Move_Element(R : System.Address) return int with Import,Convention=>C,External_Name=>"xmlTextReaderMoveToElement";
   procedure Release(R : System.Address) with Import,Convention=>C,External_Name=>"xmlFreeTextReader";
   function Len(P : System.Address; Maximum : size_t) return size_t with Import,Convention=>C,External_Name=>"strnlen";
   function As_Ptr is new Ada.Unchecked_Conversion(System.Address,Interfaces.C.Strings.chars_ptr);
   procedure Free is new Ada.Unchecked_Deallocation(Bytes,Buffer_Access);
   procedure Copy(P : System.Address; V : out MC_Text.Value; Status : out Outcome) is
      N : size_t;
   begin
      V:=MC_Text.Empty; Status:=Invalid_Input; if P=System.Null_Address then return; end if;
      N:=Len(P,4_097); if N>4_096 then Status:=Exhausted; return; end if;
      MC_Text.Set(V,Interfaces.C.Strings.Value(As_Ptr(P),N),Status);
   end;
   procedure Open(Data : Bytes; R : in out Reader; Status : out Outcome) is
   begin
      Status:=Invalid_Input;
      if R.Handle/=System.Null_Address or else Data'Length=0 or else Data'Length>262_144 then return; end if;
      for I in Data'Range loop
         if not (Data(I) in 9|10|13 or else Data(I) in 32..126) then return; end if;
         if I<Data'Last and then Data(I)=60 and then Data(I+1) in 33|63 then
            -- No <! constructs or <? instructions at all; callers strip no bytes.
            -- Native crm_mon emits no XML declaration in the qualified profile.
            Status:=Unsupported; return;
         end if;
      end loop;
      R.Buffer:=new Bytes'(Data); R.Steps:=0;
      R.Handle:=Create(R.Buffer(R.Buffer'First)'Address,int(Data'Length),System.Null_Address,System.Null_Address,2_144);
      if R.Handle=System.Null_Address then Close(R); Status:=Invalid_Input; else Status:=OK; end if;
   exception when others => Close(R); Status:=IO_Error;
   end;
   procedure Next(R : in out Reader; Available : out Boolean; Kind : out Node_Kind;
      Depth : out Natural; Name : out MC_Text.Value; Status : out Outcome) is
      RC,T,D : int;
   begin
      Available:=False; Kind:=Other_Node; Depth:=0; Name:=MC_Text.Empty; Status:=Invalid_Input;
      if R.Handle=System.Null_Address then return; end if;
      if R.Steps=16_384 then Status:=Exhausted; return; end if; R.Steps:=R.Steps+1;
      RC:=Read_Node(R.Handle);
      if RC=0 then Status:=OK; return; elsif RC/=1 then return; end if;
      Available:=True; T:=N_Type(R.Handle); D:=N_Depth(R.Handle);
      if D<0 or else D>32 or else N_NS(R.Handle)/=System.Null_Address then Status:=Unsupported; return; end if;
      Depth:=Natural(D);
      case T is
         when 1=>Kind:=Element; Copy(N_Name(R.Handle),Name,Status);
         when 15=>Kind:=End_Element; Copy(N_Name(R.Handle),Name,Status);
         when 3|13|14=>
            Kind:=Text; Copy(N_Value(R.Handle),Name,Status);
            -- Whitespace is handled without the printable-text helper below.
            if Status/=OK then
               declare P : constant System.Address:=N_Value(R.Handle); N : size_t; begin
                  if P=System.Null_Address then return; end if; N:=Len(P,4_097);
                  if N>4_096 then Status:=Exhausted; return; end if;
                  for C of String'(Interfaces.C.Strings.Value(As_Ptr(P),N)) loop
                     if C not in ' '|ASCII.HT|ASCII.LF|ASCII.CR then Status:=Invalid_Input; return; end if;
                  end loop; Name:=MC_Text.Empty; Status:=OK;
               end;
            end if;
         when others=>Status:=Unsupported;
      end case;
   end;
   procedure Attribute(R : in out Reader; Name : String; V : out MC_Text.Value; Status : out Outcome) is
      C : aliased char_array:=To_C(Name); RC : int;
   begin
      V:=MC_Text.Empty; Status:=Invalid_Input;
      if R.Handle=System.Null_Address or else Name'Length=0 or else Name'Length>128 then return; end if;
      RC:=Move_Attr(R.Handle,C'Address); if RC/=1 then return; end if;
      Copy(N_Value(R.Handle),V,Status); RC:=Move_Element(R.Handle);
      if RC/=1 then Status:=Invalid_Input; end if;
   end;
   procedure Close(R : in out Reader) is
   begin
      if R.Handle/=System.Null_Address then Release(R.Handle); R.Handle:=System.Null_Address; end if;
      if R.Buffer/=null then Free(R.Buffer); end if;
   end;
end MC_XML;

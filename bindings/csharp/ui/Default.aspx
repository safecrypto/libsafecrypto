<%@ Page Language="C#" Inherits="webapp.Default" MasterPageFile="~/MasterPage.master" CodeBehind="Default.aspx.cs"%>

<asp:Content ID="Content1" ContentPlaceHolderID="head" runat="server">
</asp:Content>
<asp:Content ID="Content2" ContentPlaceHolderID="content" runat="server">

	<div style="width:100%;">
	    <div class="jumbotron" style="background-image: url(~/Images/Header.jpg);
	    background-size: cover;
	    background-repeat: no-repeat;
	    background-position: center center;
	    height:250px;
	    color: transparent;
	    text-shadow: black 0.3em 0.3em 0.3em;">
	    </div>
    </div>

    <div class="row">
	    <div class="col-md-4" style="height:100%;">
	        <div class="thumbnail mythumbnail">
		        <div class="caption mycaption">
		            <asp:LinkButton class="btn btn-primary btn-lg" id="encBtn" runat="server"
		                OnClick="encBtnClicked" Width="150px" >
		                <span class="glyphicon glyphicon-lock"></span>&nbsp;&nbsp;Encryption
		            </asp:LinkButton>
		            <p style="font-size:20px;margin-top:10px;">Demonstration of LBC-based Encryption schemes.</p>
		        </div>
		    </div>
		</div>
		<div class="col-md-4" style="height:100%;">
	        <div class="thumbnail mythumbnail">
		        <div class="caption mycaption">
		            <asp:LinkButton class="btn btn-primary btn-lg" id="sigBtn" runat="server"
		                OnClick="sigBtnClicked" Width="150px" >
		                <span class="glyphicon glyphicon-pencil"></span>&nbsp;&nbsp;Signatures
		            </asp:LinkButton>
		            <p style="font-size:20px;margin-top:10px;">Demonstration of LBC-based Signature schemes.</p>
		        </div>
		    </div>
		</div>
		<div class="col-md-4" style="height:100%;">
	        <div class="thumbnail mythumbnail">
		        <div class="caption mycaption">
	        	    <asp:LinkButton class="btn btn-primary btn-lg" id="ibeBtn" runat="server"
		                OnClick="ibeBtnClicked" Width="150px" >
		                <span class="glyphicon glyphicon-user"></span>&nbsp;&nbsp;IBE
		            </asp:LinkButton>
		            <p style="font-size:20px;margin-top:10px;">Demonstration of LBC-based Identity-Based Encryption schemes.</p>
		        </div>
		    </div>
	    </div>
    </div>

</asp:Content>

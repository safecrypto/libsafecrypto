<%@ Page Language="C#" Inherits="webapp.Signatures" MasterPageFile="~/MasterPage.master"
CodeBehind="Signatures.aspx.cs"%>

<asp:Content ID="Content1" ContentPlaceHolderID="head" runat="server">
</asp:Content>
<asp:Content ID="Content2" ContentPlaceHolderID="content" runat="server">

	<div style="display:flex; flex-direction:row; width:100%; margin-bottom:15px;">
	    <div style="flex-item">
	        <div class="input-group">
	        <span class="input-group-addon" id="sig-addon">Signature Scheme</span>
	        <asp:DropDownList id="SchemeList"
                CssClass="form-control btn btn-primary"
                AutoPostBack="True"
                OnSelectedIndexChanged="SchemeList_Change"
                runat="server"
                Width="100%"
                ToolTip="Select a signature scheme">
                <asp:ListItem Selected="True" Value="BLISS-B-IV"> BLISS-B-IV </asp:ListItem>
                <asp:ListItem> BLISS-B-III </asp:ListItem>
                <asp:ListItem> BLISS-B-II </asp:ListItem>
                <asp:ListItem> BLISS-B-I </asp:ListItem>
                <asp:ListItem> BLISS-B-0 </asp:ListItem>
            </asp:DropDownList>
            </div>
        </div>
        <div style="flex-item">
            <div class="input-group" style="margin-left:10px;">
	        <span class="input-group-addon" id="cfg-addon">Configuration</span>
            <button type="button" class="form-control btn btn-primary" style="width:60px;"
                data-toggle="modal" data-target="#cfgModal" title="Modify signature scheme settings">
                <span class="glyphicon glyphicon-cog"></span>
            </button>
            </div>
        </div>
    </div>

    <div class="row">
        <div class="col-md-6">
            <div class="panel panel-primary">
                <div class="panel-heading">Key Generation</div>

                <div class="panel-body" >
	                <div class="btn-group" role="group" aria-label="KeyPairCtrl" style="margin-bottom:5px;">
	                    <asp:LinkButton runat="server" id="KeyGenBtn" CssClass="btn btn-primary" Width="40px"
	                        OnClick="KeyGenBtn_Click" ToolTip="Generate a random key pair">
	                        <span class="glyphicon glyphicon-random"></span>
	                    </asp:LinkButton>
	                    <asp:LinkButton runat="server" id="KeyLoadBtn" CssClass="btn btn-primary disabled" Width="40px" Enabled="false">
	                        <span class="glyphicon glyphicon-open"></span>
	                    </asp:LinkButton>
	                    <asp:LinkButton runat="server" id="KeySaveBtn" CssClass="btn btn-primary disabled" Width="40px" Enabled="false">
	                        <span class="glyphicon glyphicon-save"></span>
	                    </asp:LinkButton>
	                </div>

	                <asp:UpdatePanel runat="server" id="UpdatePanel_Keys" UpdateMode="Conditional">
	                    <ContentTemplate>
	                    	<div class="panel panel-info">
	                            <div class="panel-heading">Private Key</div>
	                            <div class="panel-body" >
		                            <asp:Label id="PrivKeyText" runat="server" Style="word-wrap:break-word;"
		                                Width="100%" Font-Size="0.7em" />
		                        </div>
		                    </div>
		                    <div class="panel panel-info">
	                            <div class="panel-heading">Public Key</div>
	                            <div class="panel-body" >
	                            	<asp:Label id="PubKeyText" runat="server" Style="word-wrap:break-word;"
	                                	Width="100%" Font-Size="0.7em" />
	                            </div>
		                    </div>
	                    </ContentTemplate>
	                </asp:UpdatePanel>
	            </div>
            </div>
        </div>
        <div class="col-md-6">
            <div class="panel panel-primary">
                <div class="panel-heading">Signature</div>

                <div class="panel-body" >
	                <div style="display:flex; flex-direction:row; width:100%;">
		                <div>
			                <div class="btn-group" role="group" aria-label="SigCtrl"
			                    style="margin-bottom:5px;margin-right:10px;width:90px;">
			                    <asp:LinkButton runat="server" id="SigBtn" CssClass="btn btn-primary disabled"
			                        Width="40px" Text="Random" OnClick="SigBtn_Click" Enabled="false"
			                        ToolTip="Generate a random message and associated signature" >
			                        <span class="glyphicon glyphicon-random"></span>
			                    </asp:LinkButton>
			                    <asp:LinkButton runat="server" id="SigFileBtn" CssClass="btn btn-primary disabled"
			                        Width="40px" Enabled="false">
			                        <span class="glyphicon glyphicon-open-file"></span>
			                    </asp:LinkButton>
			                </div>
		                </div>
	                </div>

	                <asp:UpdatePanel runat="server" id="UpdatePanel_Sigs" UpdateMode="Conditional">
	                    <ContentTemplate>
	                    	<div class="panel panel-info">
	                            <div class="panel-heading">Message</div>
	                            <div class="panel-body" >
	                            	<asp:Label id="InputText" runat="server" Style="word-wrap:break-word;"
	                                	Width="100%" Font-Size="0.7em" />
	                            </div>
		                    </div>
	                    	<div class="panel panel-info">
	                            <div class="panel-heading">Signature</div>
	                            <div class="panel-body" >
                            		<asp:Label id="SignatureText" runat="server" Style="word-wrap:break-word;"
                                		Width="100%" Font-Size="0.7em" />
                                </div>
	                        </div>
	                        <div style="margin-top:10px">
	                            <div class="input-group">
	        	                    <span class="input-group-addon" id="ver-addon">Verification</span>
		                            <asp:Label runat="server" id="VerBtn" CssClass="form-control btn btn-default"
		                                Width="60px" >
	            			        </asp:Label>
	                            </div>
	                        </div>
	                        <asp:Label runat="server" Text="RatioTest" Width="100px"></asp:Label>
	                        <asp:Label runat="server" id="RatioTest" Text="" Width="100px"></asp:Label>
	                    </ContentTemplate>
	                </asp:UpdatePanel>
	            </div>
            </div>
        </div>
    </div>

    <script type="text/javascript">
        function closeModalCfg() {
            $('#cfgModal').modal('hide');
            $('body').removeClass('modal-open');
            $('.modal-backdrop').remove();
        }
    </script>

    <div id="cfgModal" class="modal fade" role="dialog" style="display: none; "
        data-backdrop="static" data-keyboard="false">
        <div class="modal-dialog">

            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal">&times;</button>
                    <h4 class="modal-title">Signature Configuration</h4>
                </div>
                <div class="modal-body">
                    <div class="input-group" style="margin-bottom:5px" >
	                    <span class="input-group-addon" style="width:150px" id="reduce-addon">
	                        Reduction
	                    </span>
	                    <asp:DropDownList id="SigReduceList"
                            CssClass="form-control btn btn-primary"
                            AutoPostBack="False"
                            runat="server"
                            Width="160px">
                            <asp:ListItem Selected="True" Value="None"> Barrett </asp:ListItem>
                            <asp:ListItem> Proth </asp:ListItem>
                            <asp:ListItem> None </asp:ListItem>
                        </asp:DropDownList>
                    </div>
                    <div class="input-group" style="margin-bottom:5px" >
	                    <span class="input-group-addon" style="width:150px" id="sampling-addon">
	                        Sampling
	                    </span>
	                    <asp:DropDownList id="SigSamplingList"
                            CssClass="form-control btn btn-primary"
                            AutoPostBack="False"
                            runat="server"
                            Width="160px">
                            <asp:ListItem Selected="True" Value="None"> CDF Gaussian </asp:ListItem>
                            <asp:ListItem> BAC Gaussian </asp:ListItem>
                            <asp:ListItem> Huffman Gaussian </asp:ListItem>
                        </asp:DropDownList>
                    </div>
                    <div class="input-group" style="margin-bottom:5px" >
	                    <span class="input-group-addon" style="width:150px" id="csprng-addon">
	                        CSPRNG
	                    </span>
	                    <asp:DropDownList id="SigCsprngList"
                            CssClass="form-control btn btn-primary"
                            AutoPostBack="False"
                            runat="server"
                            Width="160px">
                            <asp:ListItem Selected="True" Value="None"> System </asp:ListItem>
                            <asp:ListItem> ISAAC </asp:ListItem>
                            <asp:ListItem> AES </asp:ListItem>
                            <asp:ListItem> CHACHA20 </asp:ListItem>
                        </asp:DropDownList>
                    </div>
	                <div class="input-group" style="margin-bottom:5px" >
		                <span class="input-group-addon" style="width:150px" id="sig-addon">
		                    <span class="glyphicon glyphicon-compressed"></span>
		                </span>
		                <asp:DropDownList id="SigEntropyList"
	                        CssClass="form-control btn btn-primary"
	                        AutoPostBack="False"
	                        runat="server"
	                        Width="160px">
	                        <asp:ListItem Selected="True" Value="None"> None </asp:ListItem>
	                        <asp:ListItem> BAC </asp:ListItem>
	                        <asp:ListItem> BAC with RLE </asp:ListItem>
	                        <asp:ListItem> Huffman </asp:ListItem>
	                        <asp:ListItem> strongSwan Huffman </asp:ListItem>
	                    </asp:DropDownList>
	                </div>
                    <div class="input-group" style="margin-bottom:5px">
	                    <span class="input-group-addon" style="width:150px" id="hash-addon">
	                        Hash Algorithm
	                    </span>
	                    <asp:DropDownList id="SigHashList"
                            CssClass="form-control btn btn-primary"
                            AutoPostBack="False"
                            runat="server"
                            Width="160px">
                            <asp:ListItem Selected="True" Value="None"> SHA3-512 </asp:ListItem>
                            <asp:ListItem> SHA3-384 </asp:ListItem>
                            <asp:ListItem> SHA3-256 </asp:ListItem>
                            <asp:ListItem> SHA3-224 </asp:ListItem>
                            <asp:ListItem> SHA2-512 </asp:ListItem>
                            <asp:ListItem> SHA2-384 </asp:ListItem>
                            <asp:ListItem> SHA2-256 </asp:ListItem>
                            <asp:ListItem> SHA2-224 </asp:ListItem>
                            <asp:ListItem> BLAKE2-512 </asp:ListItem>
                            <asp:ListItem> BLAKE2-384 </asp:ListItem>
                            <asp:ListItem> BLAKE2-256 </asp:ListItem>
                            <asp:ListItem> BLAKE2-224 </asp:ListItem>
                            <asp:ListItem> WHIRLPOOL </asp:ListItem>
                        </asp:DropDownList>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-default" id="CfgApplyBtn"
                        data-dismiss="modal" runat="server" onserverclick="CfgApplyBtn_Click" >
                        Apply
                    </button>
                </div>
            </div>

        </div>
    </div>

</asp:Content>



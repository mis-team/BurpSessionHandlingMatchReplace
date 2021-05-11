package burp;

import java.awt.Component;
import java.util.List;

import com.google.gson.Gson;

public class BurpExtender implements IBurpExtender, ISessionHandlingAction, ITab
{
	private IExtensionHelpers helpers;
	private MatchReplaceConfigurationPanel configuration;
	//private Config config;
	private IBurpExtenderCallbacks callbacks;

	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		//this.config = new Config(this);
		callbacks.registerSessionHandlingAction(this);
		helpers = callbacks.getHelpers();
		configuration = new MatchReplaceConfigurationPanel(this);
		callbacks.customizeUiComponent(configuration);
		callbacks.addSuiteTab(this);
	}

	public MatchReplaceConfigurationPanel getConfig() {
		return this.configuration;
	}

	public IBurpExtenderCallbacks getCallbacks() {
		return this.callbacks;
	}

	@Override
	public String getActionName() {
		return "Match and replace";
	}

	@Override
	public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems) {
		String request = helpers.bytesToString(currentRequest.getRequest());
		//List<MatchReplace> data = configuration.getData();
		List<MatchReplace> data = configuration.getData();
		for (MatchReplace element : data) {
			request = request.replaceAll(element.getMatch(), element.getReplace());
		}
		currentRequest.setRequest(helpers.stringToBytes(request));
	}

	@Override
	public String getTabCaption() {
		return "Match and replace";
	}

	@Override
	public Component getUiComponent() {
		return configuration;
	}
}
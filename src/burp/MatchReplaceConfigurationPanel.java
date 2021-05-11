package burp;

//import com.google.common.collect.Lists;

import com.google.gson.Gson;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.JFileChooser;
import javax.swing.JFrame;



@SuppressWarnings("serial")
public class MatchReplaceConfigurationPanel extends JPanel {
	
	private JTable table;
	private static final int INDEX_COL = 0;
	private static final int MATCH_COL = 1;
	private static final int REPLACE_COL = 2;
	private DefaultTableModel dataModel;
	private BurpExtender burpExtender;
	private IBurpExtenderCallbacks callbacks;
	private JTextField configFile = new JTextField("", 60);
	
	public MatchReplaceConfigurationPanel(BurpExtender burpExtender) {
		setLayout(new BorderLayout(0, 0));
		this.burpExtender = burpExtender;
		this.callbacks = burpExtender.getCallbacks();
		prepareTable();
		prepareHeader();
		prepareButtons();
	}
	
	public List<MatchReplace> getData() {
		List<MatchReplace> data = new ArrayList<>();
		int rowCount = table.getRowCount();
		for (int i = 0; i < rowCount; i++) {
			data.add(new MatchReplace((String)table.getValueAt(i, MATCH_COL), (String)table.getValueAt(i, REPLACE_COL)));
		}
		return data;
	}

	public void saveMatchReplaceTableData(String jsonData) {
		this.callbacks.saveExtensionSetting("MatchReplaceTableData", jsonData);
	}

	private void prepareTable() {
		table = new JTable();
		
		dataModel = new DefaultTableModel(new Object[][] {}, new String[] {"#", "Match", "Replace"}) {
			boolean[] columnEditables = new boolean[] {
				false, false, false
			};
			public boolean isCellEditable(int row, int column) {
				return columnEditables[column];
			}
		};
		
		table.setBounds(2, 50, 315, 32);
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		table.setFillsViewportHeight(true);
		table.setModel(dataModel);
		table.getColumnModel().getColumn(0).setPreferredWidth(30);
		table.getColumnModel().getColumn(0).setMaxWidth(30);
		table.getColumnModel().getColumn(1).setPreferredWidth(400);
		table.getColumnModel().getColumn(1).setMaxWidth(400);
		table.getColumnModel().getColumn(2).setPreferredWidth(300);
		
		JScrollPane scrollPane = new JScrollPane(table);
		add(scrollPane, BorderLayout.CENTER);
	}
	
	private JLabel createLabelURL(String url) {
		JLabel lblUrl = new JLabel(url);
		lblUrl.setForeground(Color.BLUE);
		lblUrl.setCursor(new Cursor(Cursor.HAND_CURSOR));
		lblUrl.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				try {
					Desktop.getDesktop().browse(new URI(lblUrl.getText()));
				} catch (URISyntaxException | IOException ex) {
					ex.printStackTrace();
				}
			}
		});
		return lblUrl;
	}
	
	private void prepareHeader() {
		JPanel panel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) panel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		add(panel, BorderLayout.NORTH);
		
		JLabel patternUrl = createLabelURL("https://docs.oracle.com/javase/8/docs/api/java/util/regex/Pattern.html");
		JLabel gitHubUrl = createLabelURL("https://github.com/LogicalTrust/BurpSessionHandlingMatchReplace");
		
		JButton btn = new JButton("?");
		btn.addActionListener((ev) -> {
			JOptionPane.showMessageDialog(null, new Object[] { "Pattern syntax based on:", patternUrl, "GitHub:", gitHubUrl });
		});
		
		panel.add(btn);
	}
	
	private void prepareButtons() {
		JPanel panel_1 = new JPanel();
		JPanel panel_2 = new JPanel();
		//JTextField configFile = new JTextField("", 60);


		add(panel_2,BorderLayout.NORTH);
		panel_2.add(new JLabel("Load text file ( split by : tab or comma )"));
		//panel_2.add(configFile);

		add(panel_1, BorderLayout.WEST);
		panel_1.setLayout(new BoxLayout(panel_1, BoxLayout.PAGE_AXIS));


		prepareAddButton(panel_1);
		prepareEditButton(panel_1);
		prepareRemoveButton(panel_1);
		prepareSaveButton(panel_1);
		prepareLoadButton(panel_2);
		loadConfig();
	}

	private void loadConfig(){
		try {
			List<MatchReplace> loadedData = new ArrayList<>();
			String MatchReplaceTableData = this.callbacks.loadExtensionSetting("MatchReplaceTableData");
			if (MatchReplaceTableData == null || MatchReplaceTableData.isEmpty()) {

			}
			else {
				loadedData = new Gson().fromJson(MatchReplaceTableData, new TypeToken<List<MatchReplace>>() {
				}.getType());
				int rowCount = loadedData.size();
				for (int i = 0; i < rowCount; i++) {
					//data.add(new MatchReplace((String) table.getValueAt(i, MATCH_COL), (String) table.getValueAt(i, REPLACE_COL)));
					int position =i + 1;
					dataModel.addRow(new Object[] { position, loadedData.get(i).getMatch(), loadedData.get(i).getReplace() });
				}


				//saveMatchReplaceTableData(new Gson().toJson(this.getData()));
				//this.callbacks.printOutput("Saved 2!");
			}
		}
		catch (RuntimeException e) {
			this.callbacks.printError(e.toString());
			//this.callbacks.printOutput(e.toString());
		}
	}

	private void saveConfig(){
		try {

			saveMatchReplaceTableData(new Gson().toJson(this.getData()));
			//this.callbacks.printOutput("Saved 2!");
		}
		catch (RuntimeException e) {
			this.callbacks.printError(e.toString());
			//this.callbacks.printOutput(e.toString());
		}
	}

	private void prepareLoadButton(JPanel panel_1) {
		JButton btnLoad = new JButton("Load");
		btnLoad.addActionListener((event) -> {

			JFileChooser fc = new JFileChooser();
			JFrame frame = new JFrame();
			frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

			int returnVal = fc.showOpenDialog(frame);
			if (returnVal == JFileChooser.APPROVE_OPTION) {
				File file = fc.getSelectedFile();
				try {
					BufferedReader input = new BufferedReader(new InputStreamReader(
							new FileInputStream(file)));
					String line;
					dataModel.setRowCount(0);
					int i = 1;
					while( (line = input.readLine()) != null) {
						if (line.matches(".*\\t.*")) {
							dataModel.addRow(new Object[]{i, line.split("\\t")[0], line.split("\\t")[1]});
							i++;
						}
						if (line.matches(".*,.*")) {
							dataModel.addRow(new Object[]{i, line.split(",")[0], line.split(",")[1]});
							i++;
						}
						if (line.matches(".*:.*")) {
							dataModel.addRow(new Object[]{i, line.split(":")[0], line.split(":")[1]});
							i++;
						}
					}
				saveConfig();
				} catch (Exception e) {
					e.printStackTrace();
				}
			} else {
				System.out.println("Operation is CANCELLED :(");
			}


			//this.burpExtender.getConfig().saveAutoDropRequestTableData(new Gson().toJson(autoDropRequestTable.getAutoDropRequestRules()));
		});
		panel_1.add(btnLoad);
	}

	private void prepareSaveButton(JPanel panel_1) {
		JButton btnSave = new JButton("Save");
		btnSave.addActionListener((event) -> {
			saveConfig();
		});
		panel_1.add(btnSave);
	}

	private void prepareRemoveButton(JPanel panel_1) {
		JButton btnRemove = new JButton("Delete");
		btnRemove.addActionListener((event) -> {
			int selectedRow = table.getSelectedRow();
			dataModel.removeRow(selectedRow);
			int rowCount = dataModel.getRowCount() - selectedRow;
			for (int i = 0; i < rowCount; i++) {
				dataModel.setValueAt(i + selectedRow + 1, i + selectedRow, INDEX_COL);
			}
			saveConfig();
		});
		panel_1.add(btnRemove);
	}

	private void prepareEditButton(JPanel panel_1) {
		JButton btnEdit = new JButton("Edit");
		btnEdit.addActionListener((event) -> {
			int selectedRow = table.getSelectedRow();
			JTextField match = new JTextField((String)table.getValueAt(selectedRow, MATCH_COL));
			JTextField replace = new JTextField((String)table.getValueAt(selectedRow, REPLACE_COL));
			Object[] message = {
			    "Match:", match,
			    "Replace:", replace
			};
			int option = JOptionPane.showConfirmDialog(null, message, "Edit", JOptionPane.OK_CANCEL_OPTION);
			if (option == JOptionPane.OK_OPTION) {
				table.setValueAt(match.getText(), selectedRow, MATCH_COL);
				table.setValueAt(replace.getText(), selectedRow, REPLACE_COL);
			}
			saveConfig();
		});
		panel_1.add(btnEdit);
	}

	private void prepareAddButton(JPanel panel_1) {
		JButton btnAdd = new JButton("Add");
		btnAdd.addActionListener((event) -> {
			JTextField match = new JTextField();
			JTextField replace = new JTextField();
			Object[] message = {
			    "Match:", match,
			    "Replace:", replace
			};
			int option = JOptionPane.showConfirmDialog(null, message, "Add", JOptionPane.OK_CANCEL_OPTION);
			if (option == JOptionPane.OK_OPTION) {
				int position = dataModel.getRowCount() + 1;
				dataModel.addRow(new Object[] { position, match.getText(), replace.getText() });
			}
			saveConfig();
		});
		panel_1.add(btnAdd);
	}
	
}
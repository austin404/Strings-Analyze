#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QFileDialog>
#include <QFileInfo>
#include <QFileInfoList>
#include <QFile>
#include <QDir>
#include <QVector>
#include <QMessageBox>
#include <QMimeDatabase>
#include <mythread.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->setWindowTitle("Strings Analyze");
    initComponents();
    readPatterns();
}

void MainWindow::initComponents()
{
    // Progress Bar
    ui->progressBar->setValue(0);

    // Table Widget
    ui->tableWidget->setEditTriggers(QTableWidget ::NoEditTriggers);
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->horizontalHeader()->setFixedHeight(35);
    ui->tableWidget->horizontalHeader()->setDefaultAlignment(Qt ::AlignLeft | Qt::AlignVCenter);
    ui->tableWidget->horizontalHeader()->setStretchLastSection(true);
    ui->tableWidget->setSortingEnabled(true);
    ui->tableWidget->verticalHeader()->setDefaultAlignment(Qt::AlignTop);
}

// Nothing fancy here
// File Dialog
void MainWindow ::FileDialog()
{
    QString filename = QFileDialog ::getOpenFileName(
        this,
        "Select strings dump file",
        QDir ::homePath(),
        "All files (*.*)");

    if (!filename.isNull())
    {
        QStringList temp = filename.split("/");
        this->setWindowTitle("Strings Analyze: " + temp[temp.size() - 1]);
        searchPatterns(filename);
    }
    else
    {
        exit(1);
    }
}

// This guy over here read patterns from strings-analyze-patterns folder
void MainWindow ::readPatterns()
{
    QDir dir = QDir();

    if (dir.exists("strings-analyze-patterns/Patterns/"))
    {
        recursiveFileOpen(dir.currentPath() + "/strings-analyze-patterns/Patterns");
    }
    else
    {
        QMessageBox msg;
        msg.setWindowTitle("Patter Folder not found");
        msg.setText("<b>strings-analyze-patterns folder was not found<b>");
        msg.setTextFormat(Qt::TextFormat::RichText);
        msg.setInformativeText("Download the repo from<br> <a href='https://github.com/UnrealSecurity/strings-analyze-patterns'> https://github.com/UnrealSecurity/strings-analyze-patterns</a> and place it in the same directory as executable\
    <br>Current Directory:<br><small><i>" +
                               dir.currentPath() + "</i></small>");
        msg.setDetailedText("If \"strings-analyze-patterns\" folder is already present then try running the binary from same folder");
        msg.setIcon(QMessageBox ::Critical);
        msg.exec();
        exit(1);
    }
}

void MainWindow ::recursiveFileOpen(QString path)
{
    QDir dir = QDir(path);
    QFileInfoList fileList = dir.entryInfoList(QDir ::Filter ::NoDotAndDotDot | QDir::Filter ::AllEntries);
    for (QFileInfo &f : fileList)
    {
        if (f.isDir())
            recursiveFileOpen(f.absoluteFilePath());
        else if (f.isFile() && f.fileName().right(4) == ".pat")
        {
            QVector<PatternData> pd_list = parsePattern(f.absoluteFilePath());
            this->pattern_data.append(pd_list);
        }
        else
        {
            // Why do you even exist ?
        }
    }
}

void MainWindow::noPatternFoundMsg()
{
    QMessageBox msg;
    msg.setWindowTitle("No Patterns Found");
    msg.setText("<b>No Patterns Found");
    msg.setTextFormat(Qt::TextFormat::RichText);
    msg.setIcon(QMessageBox ::Information);
    msg.exec();
}

void MainWindow::onProgress()
{
    this->lineFinished++;
    this->ui->progressBar->setValue(this->lineFinished);
}

void MainWindow::onComplete(QVector<PatternData> pdList)
{

    this->matchedPattern.append(pdList);

    for (auto thread : this->threads)
    {
        if (thread->isRunning())
            return;
    }

    ui->tableWidget->setRowCount(0); // Clearing table everytime new results comes

    for (PatternData &pd : this->matchedPattern)
    {
        pd.matched_string = this->mimeType.contains("text/") ? pd.matched_string : removeNonPritables(pd.matched_string);
        addDataToTable(pd);
    }

    if (this->matchedPattern.size() == 0 && !this->noPatterns)
    {
        this->ui->progressBar->setValue(this->lines.size());
        this->noPatterns = true;
        noPatternFoundMsg();
        return;
    }

    ui->tableWidget->resizeRowsToContents(); // For Word Wrap
    ui->tableWidget->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
}

// UwU pattern Parser
QVector<PatternData> MainWindow ::parsePattern(QString path)
{

    QVector<PatternData> pd_list;

    QFile f(path);
    f.open(QIODevice::ReadOnly);
    while (!f.atEnd())
    {

        bool is_quote = false;

        QString line = f.readLine().trimmed();
        QString temp = "";

        if (!line.isEmpty() && line.at(0) != '#')
        {
            QVector<QString> temp_list;
            for (unsigned int i = 0; i < line.size(); ++i)
            {
                if (!is_quote)
                {
                    if (line.at(i) == '"')
                        is_quote = true;
                    else
                    {
                        bool inside = false; // This is so that it doesn't add empty spaces
                        while (i < line.size() && line.at(i) != ' ')
                        {
                            inside = true;
                            temp += line.at(i);
                            ++i;
                        }
                        if (inside)
                            temp_list.push_back(temp);
                        temp = "";
                    }
                }
                else if (is_quote)
                {
                    while (true)
                    {
                        if (i >= line.size())
                            break;
                        if (line.at(i) != '"')
                            temp += line.at(i);
                        else if (line.at(i) == '"' && line.at(i - 1) == '\\' && line.at(i - 2) != '\\')
                        {
                            temp += line.at(i);
                        }
                        else if (line.at(i) == '"' && line.at(i - 1) == '\\' && line.at(i - 2) == '\\' && line.at(i - 3) == '\\' && line.at(i - 4) != '\\')
                            temp += line.at(i);
                        else
                            break;
                        ++i;
                    }
                    temp_list.push_back(temp.trimmed().replace(R"(\\\\\)", R"(\)").replace(R"(\\\\)", R"(\\)"));
                    temp = "";
                    is_quote = false;
                }
            }

            struct PatternData pd;

            if (temp_list.size() >= 4)
            {
                pd.code = temp_list.at(0).toInt();
                pd.type = temp_list.at(1);
                pd.description = temp_list.at(2);
                QRegularExpression reg(temp_list.at(3));
                pd.pattern = reg;
            }

            if (temp_list.size() == 5)
            {
                pd.flags = temp_list.at(4);
                if (pd.flags.contains("i"))
                    pd.pattern = QRegularExpression(temp_list.at(3), QRegularExpression ::CaseInsensitiveOption);
            }
            pd_list.push_back(pd);
            temp_list.clear();
        }
    }

    f.close();

    return pd_list;
}

// Adding data to table
void MainWindow::addDataToTable(PatternData pd)
{
    ui->tableWidget->insertRow(ui->tableWidget->rowCount());

    QPair<QString, QBrush> pair = getType(pd.code); // This gets the keyword for the code and the corresponding color

    bool is_bold = pd.code == 1; // This is for bold text for "Interesting"

    addRowData(pair.first, pair.second, 0, is_bold);
    addRowData(pd.line_number, pair.second, 1, is_bold);
    addRowData(pd.type, pair.second, 2, is_bold);
    addRowData(pd.description, pair.second, 3, is_bold);
    addRowData(pd.matched_string, pair.second, 4, is_bold);
}

// Adding data to a single row
void MainWindow::addRowData(QString text, QBrush color, int col, bool isBold)
{
    QTableWidgetItem *ti = new QTableWidgetItem();

    ti->setForeground(color);
    ti->setText(text.trimmed());
    ti->setTextAlignment(Qt ::AlignLeft | Qt ::AlignTop);
    // Set Bold if necessary
    if (isBold)
    {
        QFont font;
        font.setBold(true);
        ti->setFont(font);
    }

    ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, col, ti);
}

// Adding data to a single row for integer column
void MainWindow ::addRowData(int text, QBrush color, int col, bool isBold)
{
    QTableWidgetItem *ti = new QTableWidgetItem();

    ti->setForeground(color);
    ti->setData(Qt ::EditRole, text);
    ti->setTextAlignment(Qt ::AlignRight | Qt ::AlignTop);

    // Set Bold if necessary
    if (isBold)
    {
        QFont font;
        font.setBold(true);
        ti->setFont(font);
    }

    ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, col, ti);
}

// Set the keyword and color
QPair<QString, QBrush> MainWindow::getType(int code)
{
    QPair<QString, QBrush> pair;
    switch (code)
    {
    case 1:
        pair.first = "Interesting";
        pair.second = Qt::black;
        break;
    case 2:
        pair.first = "Miscellaneous";
        pair.second = Qt::darkBlue;
        break;
    case 3:
        pair.first = "Warning";
        pair.second = Qt::red;
        break;
    case 4:
        pair.first = "Suspicous";
        pair.second = Qt::darkYellow;
        break;
    default:
        pair.first = "Informative";
        pair.second = Qt::black;
    }
    return pair;
}

// Searching UwU patterns
void MainWindow::searchPatterns(QString path)
{
    QFile f(path);
    f.open(QIODevice::ReadOnly);
    this->mimeType = QMimeDatabase().mimeTypeForFile(path).name();

    while (!f.atEnd())
    {
        this->lines.push_back(f.readLine().trimmed().replace('\u0000', ""));
    }

    // For progress bar
    qsizetype total_lines = this->lines.size();
    ui->progressBar->setMinimum(0);
    ui->progressBar->setMaximum(total_lines != 0 ? total_lines : 100);

    if (total_lines == 0)
    {
        ui->progressBar->setValue(100);
        noPatternFoundMsg();
        return;
    }

    f.close();

    this->lineFinished = 1;

    int factor = this->lines.size() / this->numberOfthreads;

    if (lines.size() < numberOfthreads)
    {
        factor = this->lines.size();
        numberOfthreads = 1;
    }

    for (qsizetype i = 0, t = 0; t < this->numberOfthreads; i += factor, ++t)
    {
        qsizetype end = i + factor < this->lines.size() ? i + factor : this->lines.size() - 1;
        if (t == this->numberOfthreads - 1)
            end = this->lines.size() - 1;

        MyThread *p = new MyThread(this, this->lines, i, end, pattern_data);
        QObject ::connect(p, SIGNAL(emitProgress()), this, SLOT(onProgress()));
        QObject ::connect(p, SIGNAL(emitComplete(QVector<PatternData>)), this, SLOT(onComplete(QVector<PatternData>)));
        this->threads.push_back(p);
    }

    for (const auto thread : this->threads)
        thread->start();
}

QString MainWindow::removeNonPritables(QString str)
{

    QString temp;
    for (QChar &s : str)
    {
        if (s >= QChar(32) && s <= QChar(32 + 95))
            temp.push_back(s);
    }
    return temp.trimmed();
}

// Resizing progress bar and table when the MainWindow resizes
void MainWindow ::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    ui->progressBar->setGeometry(0, 0, width(), 10);
    ui->tableWidget->setGeometry(0, 10, width(), height() - 31);
    ui->tableWidget->setColumnWidth(1, 150);

    int temp = 0;
    for (int i = 0; i < 3; ++i)
        temp += ui->tableWidget->columnWidth(i);

    int y = (width() - temp) / 2;

    ui->tableWidget->setColumnWidth(3, y);
}

MainWindow::~MainWindow()
{
    delete ui;
}

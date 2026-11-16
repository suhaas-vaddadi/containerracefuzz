 %%
 %% csthesis.cls
 %% Copyright (c) 2025 Benjamin Williams <b.williams@staffs.ac.uk>
 %%
 %% A LaTeX template for typesetting research degree theses
 %% according to the common thesis guidelines. Previously known
 %% as lincolncsthesis. In 2025, this template was dropped in favour of 
 %% a more malleable and generic template applicable to a range of 
 %% institutions.
 %%
 %% It is worth noting that the main inspiration (and small snippets of code) 
 %% for this template was Cameron Gray's bangorcsthesis template. What a remarkable
 %% template that was.
 %%
 %% God bless you Cameron, you crazy genius.
 %%
 %% 
 %%
 %% -----------------------------------------
 %%
 %% This work may be distributed and/or modified under the
 %% conditions of the LaTeX Project Public License, either version 1.3
 %% of this license of (at your option) any later version.
 %% The latest version of this license is in
 %% http://www.latex-project.org/lppl.txt
 %% and version 1.3 or later is part of all distributions of LaTeX
 %% version 2005/12/01 or later.
 %%
 
 %%
 %% A big thanks to the following people for feedback, testing and
 %% feature suggestions:
 %%
 %% UoL:
 %% Chris Headleand, Mark Doughty, Carla Taylor-Rutterford,
 %% Bethany Davies, Kieran Hicks, Liam Mason, Jake Harrington,
 %% Ashley Knowles
 %%
 %% UoS:
 %% Bradley Davis
 %%
 %% Other institutions:
 %% Hala Haneya, Felicity Mayo, Alexander Orlow,
 %% Miriam Muller 
 %%
 
 %% CHANGELOG (started with 1.0.5)
 %%
 %% - [1.0.5, 21/04/21] 
 %%    Added notice about arabtex, added optional commands for
 %%    adding sections before thesis body to TOC
 %%
 %% - [1.0.6, 26/04/21]
 %%   Added missing \thesisSubmissionText command to override
 %%   thesis submission text
 %%
 %% - [1.0.7, 26/04/21]
 %%   Added commands to optionally omit the TOF, TOC and TOT.
 %%   Moved manual TOC entries for abstract, acknowledgements
 %%   into thesis template itself.
 %% 
 %% - [1.0.8, 04/07/25]
 %%   Changed class file to `csthesis`. Added \kbd and \todo
 %%   misc commands. Added centerPageNums option for centred
 %%   page numbers in footer.
 %%
 

% We're gonna be defining variables as long globals
% (because they might wanna split these up with extra lines)
\def\lxdef{\long\xdef}

% This class name
\def\@classname {csthesis}



% METADATA AND OPTIONS
% --------------------

% Define thesis template version and other metadata
\gdef\@templateVersion{1.0.8}
\gdef\@templateDate{04/07/2025}
\gdef\@templateAuthor{Benjamin Williams}

% It provides this class
\ProvidesClass{\@classname}[\@templateDate \@templateVersion \@templateAuthor]

% We need LaTeX2e at least
\NeedsTeXFormat{LaTeX2e}

% Article class
\LoadClass[12pt]{report}





% PACKAGES
% --------


% Packages
\RequirePackage{amsmath}
% --
\RequirePackage{ifthen}
\RequirePackage{xkeyval}
\RequirePackage[dvipsnames]{xcolor}
\RequirePackage[T1]{fontenc} % font types and character verification
\RequirePackage[english]{babel}
\RequirePackage[english]{isodate}
\RequirePackage[utf8]{inputenc}
\RequirePackage{xparse}
\RequirePackage{graphicx}
\RequirePackage{longtable}
\RequirePackage{blindtext}
\RequirePackage{parskip}
\RequirePackage{setspace}
\RequirePackage{geometry}
\RequirePackage{layout}
\RequirePackage{courier}
\RequirePackage{subcaption}
\RequirePackage{url}
\RequirePackage{hyperref}
\RequirePackage[table,figure]{totalcount}
\RequirePackage{appendix}
% -----------------
\RequirePackage{csquotes}
\RequirePackage{titlesec}
\RequirePackage{datetime2}
\RequirePackage{fancyhdr}
\RequirePackage{lmodern}




% FANCY DATE STUFF
% -----------------

\newcommand{\monthyeardate}{%
  \DTMenglishmonthname{\@dtm@month} \@dtm@year
}

\newcommand{\yeardate}{%
  \@dtm@year
}

% Another handy macro to test if there's an option
\def\ifClassOption [#1]#2 {
    \@ifclasswith{\@classname}{#1}{#2}{\empty}
}

% Another handy macro to test if there's an option + else
\def\ifClassOptionElse [#1]#2#3 {
    \@ifclasswith{\@classname}{#1}{#2}{#3}
}


% THESIS TEMPLATE VARIABLES
% -------------------------


% Define variables relevant to this thesis
\lxdef \@logo           {logo}
\lxdef \@date           {\monthyeardate}
\newcommand{\thesisSubmissionDate}[1]{\xdef\@date{#1}}
\lxdef \@degree         {Doctor of Philosophy}
\newcommand{\thesisDegree}[1]{\xdef\@degree{#1}}
\lxdef \@programme      {Computer Science}
\newcommand{\thesisProgramme}[1]{\xdef\@programme{#1}}
\lxdef \@schoolname     {School of Computer Science}
\newcommand{\thesisSchool}[1]{\xdef\@schoolname{#1}}
\lxdef \@collegename    {College of Science}
\newcommand{\thesisCollege}[1]{\xdef\@collegename{#1}}
\lxdef \@universityname {University of Wisconsin-Madison}
% ---
\newcommand{\getUniversity}{\@universityname}
\newcommand{\getAuthor}{\@author}
\newcommand{\getDate}{\@date}

\newcommand{\includePageHeaders}{\xdef\@includeheaders{yes}}
\newcommand{\thesisUniversity}[1]{\xdef\@universityname{#1}}
% -----
\newcommand{\thesisSupervisor}[1]{\xdef\@supervisor{#1}}
\newcommand{\thesisSecondSupervisor}[1]{\xdef\@secondsupervisor{#1}}
\newcommand{\thesisThirdSupervisor}[1]{\xdef\@thirdsupervisor{#1}}
% -----



% START OF THESIS
% --------------

\fancypagestyle{plain}{
    \renewcommand{\headrulewidth}{0pt}%
    \fancyhf{}%
    \ifClassOptionElse[centerPageNums]{
    	\fancyfoot[C]{\footnotesize\textbf{\thepage}}
    }{%
    	\fancyfoot[R]{\footnotesize{\thepage}}
    }  
}

\fancypagestyle{mainStyle}{
	\renewcommand{\headrulewidth}{0pt}%
	\fancyhf{}%
	%
	\ifClassOptionElse[centerPageNums]{
		\fancyfoot[C]{\footnotesize{\thepage}}
	}{%
		\fancyfoot[R]{\footnotesize\emph{\leftmark} \hspace{0.25cm} \footnotesize{\thepage}}
	}
}


\newcommand{\thesisBodyStart}{

    % Clear the page so we don't number the last page
    \cleardoublepage
    
    % Set page numbering back to 1, 2, 3 .. 
    \pagenumbering{arabic} 
}

% TOC PREAMBLE COMMANDS
% ---------------------

\newcommand{\enableManualTOCEntries}{\xdef\@manualTOCEnabled{yup}}
\newcommand{\disableTableTOCEntries}{\xdef\@disabledTableTOCEntries{yup}}

\newcommand{\manualTOCEntry}[2]{
    \@ifundefined{@manualTOCEnabled}{}{
        \addcontentsline{toc}{#1}{#2}
    }
}

\newcommand{\addChapterToTOC}[1]{\manualTOCEntry{chapter}{#1}}
\newcommand{\addSectionToTOC}[1]{\manualTOCEntry{section}{#1}}

\newcommand{\manualTOCTableEntry}[1]{
    \@ifundefined{@disabledTableTOCEntries}{
        \addChapterToTOC{#1}
    }{}
}


% TABLE OF CONTENTS, FIGURES AND TABLES
% ---------------------------

\newcommand{\turnOffTOF}{\xdef\@turnOffTOFDef{~}}
\newcommand{\turnOffTOT}{\xdef\@turnOffTOTDef{~}}
\newcommand{\turnOffTOC}{\xdef\@turnOffTOCDef{~}}

\newcommand{\thesisTOF}{
    \@ifundefined{@turnOffTOFDef}{
        \iftotalfigures
            \cleardoublepage
            \expandafter\manualTOCTableEntry{\listfigurename}
            \listoffigures
        \fi
    }{}
}

\newcommand{\thesisTOT}{
    \@ifundefined{@turnOffTOTDef}{
        \iftotaltables
            \cleardoublepage
            \expandafter\manualTOCTableEntry{\listtablename}
            \listoftables
        \fi
    }{}
}

\newcommand{\thesisTOC}{
    \@ifundefined{@turnOffTOCDef}{\tableofcontents}{}
}

\newcommand{\thesisTables}{
    \cleardoublepage
    \renewcommand{\contentsname}{Table of Contents}
    \setcounter{tocdepth}{3}
    {\setstretch{1.25}
        \thesisTOT
        \thesisTOF
        \thesisTOC
        
        % This adds the TOC to the TOC. If you don't want the
        % TOC in the TOC, then uncomment the line below.
        \expandafter\manualTOCTableEntry{\contentsname}
    }
    
    \setlength{\abovedisplayskip}{1pt}
    \setlength{\belowdisplayskip}{15pt}
}



% ABSTRACT
% -------------------------

\renewenvironment{abstract}
    {\cleardoublepage
     \addChapterToTOC{Abstract}
     \chapter*{\abstractname}
    }
    {}




% ACKNOWLEDGEMENTS
% ----------------

\newenvironment{acknowledgements}
    {\cleardoublepage
     \addChapterToTOC{Acknowledgements}
     \chapter*{Acknowledgements}
    }
    {}




% AFTER TITLE PAGE BUT BEFORE THESIS CONTENT
% ------------------------------------------
\newcommand{\afterTitlePage}{

    % Set margins for the rest of the thesis. Most guidelines 
    % state that: [left >= 40mm], [others >= 15mm]
    \newgeometry{
        nohead, 
        top=15mm,
        bottom=25mm,
        right=25mm,
        left=40mm,
        marginparwidth=0cm,
        marginparsep=0cm
    }

    % Set spacing and reset numbering
    \pagenumbering{roman}
            
    % Set double spacing (from cleanthesis.sty)
    \setstretch{1.5}
    \clubpenalty = 10000
    \widowpenalty = 10000
    \displaywidowpenalty = 10000
}









% TITLE PAGE
% -------------



% Command to override thesis submission text
\newcommand{\thesisSubmissionText}[1]{\xdef\@submissiontext{#1}}

% Print out supervisors
\newcommand{\printSupervisor}{
    %{\footnotesize \textit{Supervisor}~\@supervisor }
    %\@ifundefined{@secondsupervisor}{}
    %{\footnotesize \textit{Second Supervisor}~\@secondsupervisor }
    
    \footnotesize\begin{tabular}{rl}
        \@ifundefined{@supervisor}{}
        {\textit{Thesis Advisor} & \@supervisor \\}
        
        \@ifundefined{@secondsupervisor}{}
        {\textit{Second Supervisor} & \@secondsupervisor \\}
        
        \@ifundefined{@thirdsupervisor}{}
        {\textit{Third Supervisor} & \@thirdsupervisor }
    \end{tabular}
}

% The default title page: title, then logo, then author
\newcommand{\@titlepage}{
    \begin{titlepage}

    % Make the title
    \makeatletter
    \centering{\LARGE \@title \par} \vspace{1.5cm}
    
    % Make the logo
    \includegraphics[height=1.5in]{\@logo}\par 
    
    % Some space, then the author, then the school and university
    % name
    \vspace{1.5cm}
    {\large \@author \@ifundefined{@studentnumber}{}{\\ \@studentnumber} \par}\vspace{0.45cm}
    {\footnotesize \@schoolname \\ \vspace{0.25cm} \@collegename \\  \vspace{0.25cm}  \@universityname \par}
    
    % Some space and the submission statement
    \vspace{3cm}
    {\footnotesize \par}
    
    % Print out the supervisor
    \vspace{1cm}
    \printSupervisor
    
    % Then the fancy date!
    \vspace{1cm}
    {\footnotesize \@ifundefined{@modulecode}{}{\@modulecode \\} \@date \par}
    
	\end{titlepage}
}

% The alternate title page: logo, then title, then author
\def \@altTitlePage {
    \begin{titlepage}
    
    % Make the logo
    \makeatletter
    \centering\includegraphics[height=1.5in]{\@logo}\par 
    
    % Make the title
    \vspace{2cm}
    {\LARGE \@title\par}
    
    % Some space, then the author, then the school and university
    % name
    \vspace{1.5cm}
    {\large \@author \par}\vspace{0.45cm}
    {\footnotesize \@schoolname \\ \vspace{0.25cm} \@collegename \\  \vspace{0.25cm}  \@universityname \par}
    
    % Some space and the submission statement
    \vspace{2.5cm}
    {\footnotesize \par}
    
    % Print out the supervisor
    \vspace{1cm}
    \printSupervisor
    
    % Then the fancy date!
    \vspace{1cm}
    {\footnotesize \@date \par}
    
	\end{titlepage}
}

\newcommand{\beforeTitlePage}{
    % Set margins for the rest of the thesis. UoL guidelines 
    % state that: [left >= 40mm], [others > 15mm]
    
    
    
    \newgeometry{
        nohead, 
        top=40mm,
        bottom=25mm,
        right=30mm,
        left=40mm,
        marginparwidth=0cm,
        marginparsep=0cm
    }
}


% The default title page style is the title, logo, author style
\def \@defaultTitlePage {\@titlepage}


% Lets renew the make title command so we don't have to 
% make a custom one
\RenewDocumentCommand{\maketitle}{o}{%

  % Call function for before title page
  \beforeTitlePage
  
  % Then check which title page style to use
  \IfNoValueTF{#1}
    {\@defaultTitlePage}
    {\ifthenelse{\equal{#1}{logo-first}}
        {\@altTitlePage}
        {\@defaultTitlePage}}
    
  % Call function for after title page       
  \afterTitlePage
}






% TITLE / CHAPTERS / FIGURES / TITLESEC SPACING
% ---------------------------------------------

% Set the chapter title style
\titleformat{\chapter}[display]
{\normalfont\huge\bfseries}{\chaptertitlename\ \thechapter}{0pt}{\Huge}

% And space it out a bit
\titlespacing*{\chapter} {0pt}{0pt}{20mm}

% A fake chapter title command to emulate chapter titles
% without actually adding a chapter
\newcommand{\chapterTitle}[1]{
	\vspace*{-20mm} 
	{\normalfont\huge\bfseries#1 \par} 
	\vspace*{20mm}
}






% REFERENCING
% -----------

% Fake harvard referencing, instead of using natbib -- because
% natbib makes biblatex blow up.
\def\@importHarvard {
    \RequirePackage[
        defernumbers=true,
        backend=biber,
        bibencoding=utf8,
        natbib=true,
        hyperref=true,
        backref=true,
        urldate=long,
        style=authoryear,
        citestyle=authoryear,
        sorting=nyt
    ]{biblatex}
}

% Otherwise use ieee's style and numeric citation
\def\@importBibLaTeX {
    \RequirePackage[
        defernumbers=true,
        backend=biber,
        bibencoding=utf8,
        natbib=true,
        hyperref=true,
        backref=true,
        urldate=long,
        style=ieee,
        citestyle=numeric,
        sorting=nyt
    ]{biblatex}
}

% Import harvard if [harvard] is specified, otherwise
% standard biblatex!
\ifClassOptionElse[harvard]{\@importHarvard}{\@importBibLaTeX}


% Change to sans-serif default if specified
\ifClassOption[sfdefault]{\renewcommand{\familydefault}{\sfdefault}}


% Command for printing out references list
\newcommand{\printReferences}[1][References]{
	
	% Set some spacing up between the items
	\setlength\bibitemsep{0.35cm}
	
	% Set the line height (of actual items) to 1.0
	\setstretch{1.0}
	
	% Print out the bibliography with the given title
	\printbibliography[notkeyword={game}, title=#1]
}





% LUDOGRAPHY
% ----------


% Citation environment for games
\defbibenvironment{games}
 {\list
     {}
     {\setlength{\leftmargin}{\bibhang}%
      \setlength{\itemindent}{-\leftmargin}%
      \setlength{\itemsep}{\bibitemsep}%
      \setlength{\parsep}{\bibparsep}}}
  {\endlist}
  {\item}
  
% Prints out the ludography (all citations with the
% key "game")
\newcommand{\printLudography}[1][Ludography]{

    % Set some spacing up between the items
	\setlength\bibitemsep{0.35cm}
	
	% Set the line height (of actual items) to 1.0
	\setstretch{1.0}
	
	% Print out the bibliography with the given title
	\printbibliography[env=games, keyword={game}, title=#1]
}

% Prints out the ludography without a heading
\newcommand{\printLudographyNoHead}{

    % Set some spacing up between the items
	\setlength\bibitemsep{0.35cm}
	
	% Set the line height (of actual items) to 1.0
	\setstretch{1.0}
	
	% Print out the bibliography with the given title
	\printbibliography[heading=none, env=games, keyword={game}]
}

% Ludography environment, if you wish to put some text before
% the list of games that are printed
\newenvironment{ludography}[1][Ludography]{
  \chapter*{#1}  
}{\vspace*{1cm} \printLudographyNoHead}

% For citing games
\newcommand{\citeGame}[1]{
    \emph{\citeauthor{#1}}
}



% BLANK PAGE / QUOTE PAGE
% -----------------------

% For quote pages, copyright notices, or whatever else
\newenvironment{blankpage}[1][\unskip]{%
	
	% Check if [c] is specified, if so, then 
	% make it vertically align.. if not, then
	% just clear a double page and write some stuff
    \ifthenelse{\equal{#1}{c}}{
        \cleardoublepage
        \topskip0pt
        \vspace*{\fill}
    }{
    \cleardoublepage
    \topskip0pt
    \vspace*{1in}
    }
}{
        \vspace*{\fill}
}


% Set the page style to the main style. Set up the chapter
% mark style so that it shows the title of the chapter only.
\pagestyle{mainStyle}
\renewcommand{\chaptermark}[1]{\markboth{{#1}}{}}




% MISC COMMANDS
% -----------------------
\newcommand{\todoNote}[2]{(\emph{\textbf{#1}}: \emph{#2})}
\newcommand{\todo}[1]{\todoNote{Todo}{#1}}
\newcommand{\kbd}[1]{\texttt{#1}}


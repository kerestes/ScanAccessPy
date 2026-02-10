from abc import ABC, abstractmethod
from typing import Any, List
from dto import FileMetadata, ActionResult


class Session(ABC):
    """
    Session representa um canal ativo com um alvo remoto.

    Todas as operações expostas ao sistema são executadas através
    do método `action()`.

    A Session NÃO mantém estado lógico de navegação (pwd, cwd, etc.).
    Cada ação deve ser autocontida e dependente apenas dos argumentos
    fornecidos.
    """

    # -------------------------------------------------
    # Central dispatcher
    # -------------------------------------------------
    @abstractmethod
    def action(self, action: str, **kwargs: Any) -> ActionResult:
        """
        Executa uma ação padronizada no host remoto.

        Ações comuns (nem todas precisam ser suportadas):

        - "pwd"
            Retorna o diretório atual (quando aplicável)

        - "cd"
            Muda diretório (args: path)

        - "list_dir"
            Lista diretório não-recursivo (args: path)

        - "list_tree"
            Lista diretório recursivamente (args: path, depth)

        - "read_file"
            Lê arquivo remoto (args: path)

        - "write_file"
            Escreve arquivo remoto (args: local_path, remote_path)

        - "upload"
            Upload de arquivo (args: local_path, remote_path)

        - "download"
            Download de arquivo (args: remote_path, local_path)

        - "exec"
            Executa comando shell (args: command)
            Apenas protocolos que suportam shell (SSH, Telnet)

        Deve lançar NotImplementedError se a ação não for suportada.
        """
        raise NotImplementedError

    # -------------------------------------------------
    # File primitives (helpers internos)
    # -------------------------------------------------
    @abstractmethod
    def read_file(self, path: str) -> bytes:
        """
        Lê o conteúdo bruto de um arquivo remoto.
        """
        raise NotImplementedError

    @abstractmethod
    def write_file(self, local_path: str, remote_path: str):
        """
        Grava ou sobrescreve um arquivo remoto.
        """
        raise NotImplementedError

    @abstractmethod
    def list_dir(self, path: str) -> List[FileMetadata]:
        """
        Lista arquivos/diretórios em um caminho remoto
        (não recursivo).
        """
        raise NotImplementedError

    @abstractmethod
    def list_tree(self, path: str, depth: int) -> List[FileMetadata]:
        """
        Lista arquivos/diretórios recursivamente.
        """
        raise NotImplementedError

    # -------------------------------------------------
    # Transfer
    # -------------------------------------------------
    @abstractmethod
    def upload(self, local_path: str, remote_path: str):
        """
        Envia arquivo local para o host remoto.
        """
        raise NotImplementedError

    @abstractmethod
    def download(self, remote_path: str, local_path: str):
        """
        Baixa arquivo remoto para o host local.
        """
        raise NotImplementedError

    # -------------------------------------------------
    # Lifecycle
    # -------------------------------------------------
    @abstractmethod
    def close(self):
        """
        Encerra a sessão com o host remoto.
        """
        raise NotImplementedError

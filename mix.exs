# Copyright 2022 Agile Data, Inc <code@mftlabs.io>

defmodule AmpsCore.MixProject do
  use Mix.Project

  def project do
    [
      app: :amps_core,
      version: "0.1.0",
      elixir: "~> 1.12",
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [{:jetstream, git: "https://github.com/aram0112/jetstream"}]
  end
end

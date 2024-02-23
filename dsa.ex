defmodule DSA do
  defp hash(m), do: :crypto.hash(:sha3_512, m) |> :binary.decode_unsigned

  defp exp(_, 0, m) when m > 0, do: rem(1, m)
  defp exp(a, b, m) when m > 0 do # a^b mod m
  [1 | ds] = Integer.digits(b, 2)
  [a | Enum.scan(ds, a, fn _x, a -> rem(a*a, m) end)] # repeated squaring
    |> Enum.reverse |> Enum.zip_reduce([1 | ds], 1, &rem(&1**&2*&3, m))
  end

  def kgen do
    {h, _} = System.cmd "openssl",
      ["prime", "-generate", "-bits", "512", "-safe", "-hex"]
    {p, _} = Integer.parse(h, 16)
    q = div(p - 1, 2)                    # p = 2q + 1 because p is safe
    g = Enum.random(0..p-1) |> exp(2, p) # g = r^2 mod p, element of order q
    # because r <- Zp, (r^2)^q = r^(2q) = r^(p - 1) = 1 (mod p) (Fermat)
    x = Enum.random(0..q-1)
    y = exp(g, x, p)
    {{p, q, g, y}, {p, q, g, y, x}}
  end

  def sign m, {p, q, g, y, x} do
    t = Enum.random 0..q-1
    r = exp(g, t, p)
    c = hash(Integer.to_string(r) <> Integer.to_string(y) <> m) |> rem(q)
    s = t + c*x |> rem(q)
    {r, s}
  end

  def verify m, {r, s}, {p, q, g, y} do
    c = hash(Integer.to_string(r) <> Integer.to_string(y) <> m) |> rem(q)
    exp(g, s, p) == r*exp(y, c, p) |> rem(p)
  end

  # two functions for signing and verifying files (because they can be written
  # nicely in Elixir)
  def sign_file!(path, private_key), do:
    path |> Path.expand |> File.read! |> sign(private_key)

  def verify_file!(path, signature, public_key), do:
    path |> Path.expand |> File.read! |> verify(signature, public_key)
end

defmodule DSAtest do
  def test_byte_code do
    {public_key, private_key} = DSA.kgen
    # and for my next trick, I will compile this very file and sign the
    # bytecode of each module
    Code.compile_file("dsa.ex") |> Enum.map(fn
      {_module, byte_code} -> {byte_code, DSA.sign(byte_code, private_key)}
    end) |> Enum.map(fn
      {byte_code, signature} -> DSA.verify(byte_code, signature, public_key)
    end) # will return a list of [true, true] because verification is correct
  end

  def test_file!(path) do
    {public_key, private_key} = DSA.kgen
    signature = DSA.sign_file!(path, private_key)

    IO.write("Signature:\n\n")
    IO.inspect(signature)
    IO.write("\n")

    IO.write("Verifing with correct signature: ")
    DSA.verify_file!(path, signature, public_key) |> IO.inspect # true

    IO.write("Verifing with altered signature: ")
    {r, s} = signature
    DSA.verify_file!(path, {r, s + 1}, public_key) |> IO.inspect # false
    :ok
  end

  # let's also sign the source code of this file
  def test_source, do: test_file!("dsa.ex")

  # the following two require root privileges and might require different files
  # to the ones mentioned here depending on your system and setup. Should work
  # for typical Linux systems. It might not work if your disk contents don't
  # fit in RAM + SWAP
  def sign_the_entire_fucking_hdd!, do: test_file!("/dev/sda2")
  def sign_the_entire_fucking_ssd!, do: test_file!("/dev/nvme0n1p2")
  # wow you are letting me run crypto fucntions on your disk?
  # I could encrypt it whole you know

  def test_large_message do # takes some time
    {m, _} = System.cmd "openssl", ["rand", "-base64", "1000000000"] # 1GB
    # If you have enough RAM you can try generating larger data
    # you can also try
    #   $ openssl rand -base64 5000000000 > 5GB_file.txt
    # and then DSAtest.test_file!("5GB_file.txt")

    {public_key, private_key} = DSA.kgen
    signature = DSA.sign(m, private_key)

    IO.write("Signature:\n\n")
    IO.inspect(signature)
    IO.write("\n")

    IO.write("Verifing with correct signature: ")
    DSA.verify(m, signature, public_key) |> IO.inspect # true

    IO.write("Verifing with altered signature: ")
    {r, s} = signature
    DSA.verify(m, {r, s + 1}, public_key) |> IO.inspect # false
    :ok
  end
end
